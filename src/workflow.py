# -*- coding: utf-8 -*-
import hashlib
import time

import alfred
import otp
from storage.apple_keychain_storage import AppleKeychainStorage
from storage.exceptions import StorageError
from storage.storage_migration_assistant import StorageMigrationAssistant


class AlfredGAuth(alfred.AlfredWorkflow):
    _reserved_words = ['add', 'update', 'remove']

    def __init__(self, max_results=21):
        self.max_results = max_results

        self._storage = AppleKeychainStorage()

    def config_get_account_token(self, account):
        secret = self._storage.get_account_secret(account)
        key = otp.get_hotp_key(secret)

        return otp.get_totp_token(key)

    def filter_by_account(self, account, query):
        return len(query.strip()) and not query.lower() in str(account).lower()

    def account_item(self, account, token, uid=None):
        return alfred.Item({u'uid': alfred.get_uid(uid), u'arg': token,
                            u'autocomplete': account}, account,
                           f'Post {token} at cursor', 'icon.png')

    def time_remaining_item(self):
        # The uid for the remaining time will be the current time,
        # so it will appear always at the last position in the list
        time_remaining = otp.get_totp_time_remaining()
        return alfred.Item({u'uid': time.time(), u'arg': '', u'valid': 'no'},
                           f'Time Remaining: {time_remaining}s',
                           None, 'time.png')

    def search_by_account_iter(self, query):
        if self.is_command(query):
            return

        i = 0
        for account in self._storage.get_accounts():
            if self.filter_by_account(account, query):
                continue

            token = self.config_get_account_token(account)
            uid = hashlib.md5(account.encode()).hexdigest()
            yield self.account_item(uid=uid, account=account, token=token)
            i += 1

            # Ensure that there is space for the "Time Remaining..." item.
            if i == self.max_results - 1:
                break

        if i > 0:
            yield self.time_remaining_item()
        else:
            yield self.warning_item('Account not found',
                                    f'There is no account matching "{query}" '
                                    f'on your Apple Keychain.')

    def do_search_by_account(self, query):
        if not self._init_storage() or self._handle_empty_storage():
            return

        self.write_items(self.search_by_account_iter(query))

    def _init_storage(self):
        state = self._storage.get_keychain_state()

        if state == AppleKeychainStorage.STATE_KEYCHAIN_MISSING:
            item = alfred.Item({u'uid': 0, u'arg': 'create_storage'},
                               'Create Apple Keychain',
                               'No Apple Keychain found. '
                               'A new one will be created on the next step.',
                               'warning.png')
            self.write_item(item)

            return False

        if state == AppleKeychainStorage.STATE_KEYCHAIN_LOCKED:
            item = alfred.Item({u'uid': 0, u'arg': 'unlock_storage'},
                               'Unlock Apple Keychain',
                               'Apple Keychain is locked. '
                               'Enter its password on the next step.',
                               'warning.png')
            self.write_item(item)

            return False

        return True

    def do_create_storage(self, query):
        keychain_name = self._storage.get_keychain_name()

        if self._storage.create_keychain():
            self.write_text(f'Apple Keychain Created|'
                            f'Apple Keychain "{keychain_name}" is now ready '
                            f'for use.')
        else:
            self.write_text(
                f'Apple Keychain Not Created|The process was canceled. '
                f'Apple Keychain "{keychain_name}" was not created.')

    def do_unlock_storage(self, query):
        keychain_name = self._storage.get_keychain_name()

        if self._storage.unlock_keychain():
            self.write_text(f'Apple Keychain Unlocked|'
                            f'Apple Keychain "{keychain_name}" '
                            f'is now accessible.')
        else:
            self.write_text(
                f'Failed to unlock Apple Keychain|The process was canceled. '
                f'Apple Keychain "{keychain_name}" remains locked.')

    def _handle_empty_storage(self):
        # Don't recommend migration from Plain-text,
        # when user already started using Apple Keychain.
        if not self._storage.is_empty():
            return False

        migration_assistant = StorageMigrationAssistant(self._storage)

        # No data to migrate.
        if not migration_assistant.can_migrate:
            item = self.warning_item(title='GAuth is not yet configured',
                                     message='You must use "Add a new secret" '
                                             'to add your secrets into '
                                             'Apple Keychain.')
            self.write_item(item)

            return True

        source_storage_file = migration_assistant.get_source_storage_file()
        item = alfred.Item({u'uid': 0, u'arg': 'migrate_storage'},
                           'Migrate 2FA accounts to Apple Keychain',
                           f'Removes "{source_storage_file}" file '
                           f'after migration.',
                           'warning.png')
        self.write_item(item)

        return True

    def do_migrate_storage(self, query):
        migration_assistant = StorageMigrationAssistant(self._storage)

        try:
            migrated_account_count = migration_assistant.migrate()

            source_storage_file = migration_assistant.get_source_storage_file()
            self.write_text(
                f'Migration results|'
                f'Migrated {migrated_account_count} accounts. '
                f'The "{source_storage_file}" file was removed.')
        except StorageError as e:
            self.write_text(f'Migration results|Error: {e}')

    def do_add_account(self, query):
        keychain_state = self._storage.get_keychain_state()

        if keychain_state != AppleKeychainStorage.STATE_KEYCHAIN_UNLOCKED:
            self.write_text(f'Account creation failed|'
                            f'Apple Keychain is {keychain_state}.')

            return

        try:
            account, secret = query.split(',', 1)
            account = account.strip()
            secret = secret.strip()
        except ValueError:
            self.write_text('Account creation failed|Invalid arguments!\n'
                            'Please enter: account, secret.')

            return

        try:
            if self._storage.add_account(account, secret):
                self.write_text(f'Account creation succeeded|'
                                f'A new "{account}" account was added.')
            else:
                self.write_text(f'Account creation failed|'
                                f'Account "{account}" already exists.')
        except StorageError as e:
            self.write_text(f'Account creation failed|Error:{e}')

    def do_generate_qrcode(self, query):
        keychain_state = self._storage.get_keychain_state()

        if keychain_state != AppleKeychainStorage.STATE_KEYCHAIN_UNLOCKED:
            self.write_text(f'QRCode generation failed|'
                            f'Apple Keychain is {keychain_state}.')

            return

        filename = f"~/Desktop/{query.replace('/', '-')}.png"

        try:
            self._storage.generate_account_qrcode(query, filename)
            self.write_text(f'QRCode was generated successfully|'
                            f'Filename: {filename}')
        except StorageError as e:
            self.write_text(f'QRCode generation failed|Error:{e}')


def main(action, query):
    alfred_gauth = AlfredGAuth()
    alfred_gauth.route_action(action, query)


if __name__ == '__main__':
    if len(alfred.args()) < 2:
        query = ''
    else:
        query = alfred.args()[1]

    main(action=alfred.args()[0], query=query)
