import os
import subprocess
import re
# import sys
from urllib.parse import quote

import otp
from storage.exceptions import StorageError


class AppleKeychainStorage:
    STATE_KEYCHAIN_MISSING = 'missing'
    STATE_KEYCHAIN_LOCKED = 'locked'
    STATE_KEYCHAIN_UNLOCKED = 'unlocked'

    def __init__(self, name='alfred-gauth'):
        self._data = {}
        self._name = name
        self._file = name + '.keychain-db'
        self._state = None

        if self._keychain_exists():
            self._state = (
                self.STATE_KEYCHAIN_LOCKED
                if self._keychain_locked() else self.STATE_KEYCHAIN_UNLOCKED
            )
        else:
            self._state = self.STATE_KEYCHAIN_MISSING

        if self._state == self.STATE_KEYCHAIN_UNLOCKED:
            self._read_storage()

    def get_keychain_name(self):
        return self._name

    def get_keychain_state(self):
        return self._state

    def create_keychain(self):
        if self._keychain_exists():
            raise StorageError(
                f'Apple Keychain "{self._name}" already exists.'
            )

        try:
            # Create the keychain.
            self._run_command(
                ['security', 'create-keychain', '-P', self._file]
            )

            # Align the keychain settings with the 'login' keychain
            # (no-timeout & no-lock-on-sleep).
            self._run_command(
                ['security', 'set-keychain-settings', self._file]
            )

            # Make the keychain accessible from the "Keychain Access" app.
            self._add_to_keychain_access_app()
        except StorageError:
            return False

        # Don't read storage, because created keychain is empty.
        self._state = self.STATE_KEYCHAIN_UNLOCKED

        return True

    def _add_to_keychain_access_app(self):
        user_keychains = self._get_user_keychains()
        user_keychains.append(self._get_resolved_file())

        # Removes duplicates.
        user_keychains = list(set(user_keychains))

        self._run_command(
            ['security', 'list-keychains', '-d', 'user', '-s'] + user_keychains
        )

    def _get_user_keychains(self):
        results = []
        lines = self._run_command(
            ['security', 'list-keychains', '-d', 'user']
        )

        for line in lines:
            results.append(line.strip('" '))

        return results

    def _keychain_exists(self):
        # The "security list-keychains -d user" command
        # only shows keychains from the "Keychain Access" app.
        return os.path.isfile(self._get_resolved_file())

    def _get_resolved_file(self):
        return os.path.expanduser('~/Library/Keychains/' + self._file)

    def unlock_keychain(self):
        if not self._keychain_locked():
            raise StorageError(
                f'Apple Keychain "{self._name}" is already unlocked.'
            )

        try:
            self._run_command(
                ['security', 'unlock-keychain', '-u', self._file]
            )
        except StorageError:
            return False

        self._state = self.STATE_KEYCHAIN_UNLOCKED
        self._read_storage()

        return True

    def _keychain_locked(self):
        try:
            self._run_command(
                ['security', 'unlock-keychain', '-p', '', self._file]
            )
        except StorageError:
            return True

        return False

    def generate_account_qrcode(self, account, filename):
        absolute_filename = os.path.expanduser(filename)

        try:
            with open(absolute_filename, 'w') as outfile:
                subprocess.run(
                    ['qr', self._get_account_uri(account)], stdout=outfile
                )
        except FileNotFoundError as e:
            raise StorageError(
                'Run this command to install needed libraries\n'
                'pip install "qrcode[pil]"'
            ) from e
        except subprocess.CalledProcessError as e:
            raise StorageError(f'QRCode generation failed ({e})') from e

    def _get_account_uri(self, account):
        secret = self.get_account_secret(account)

        try:
            issuer, username = account.split(' - ', 1)
        except ValueError:
            raise StorageError(
                'Account must be in "issuer - username" format '
                'for QRCode generation.'
            )

        return (
            f'otpauth://totp/{quote(issuer)}:{quote(username)}?'
            f'secret={quote(secret)}&issuer={quote(issuer)}'
        )

    def is_empty(self):
        self._assert_keychain_accessible()

        return not self._data

    def get_account_secret(self, account):
        self._assert_keychain_accessible()

        if account not in self._data:
            raise StorageError(f'Account "{account}" not found.')

        return self._data[account]

    def get_accounts(self):
        self._assert_keychain_accessible()

        return self._data.keys()

    def add_account(self, account, secret):
        self._assert_keychain_accessible()

        if not otp.is_otp_secret_valid(secret):
            raise StorageError(
                f'Account "{account}" has invalid secret:\n{secret}'
            )

        if account in self._data:
            return False

        self._run_command(
            [
                'security',
                'add-generic-password',
                '-a', self._name,
                '-s', account,
                '-w', secret,
                self._file,
            ]
        )
        self._data[account] = secret

        return True

    def delete_account(self, account):
        self._assert_keychain_accessible()

        if account not in self._data:
            raise StorageError(f'Account "{account}" not found.')

        self._run_command(
            [
                'security',
                'delete-generic-password',
                '-a', self._name,
                '-s', account,
                self._file,
            ]
        )
        del self._data[account]

    def _assert_keychain_accessible(self):
        if self._state != self.STATE_KEYCHAIN_UNLOCKED:
            raise StorageError(
                f'Apple Keychain "{self._name}" is {self._state}.'
            )

    def _read_storage(self):
        self._data = self._parse(self._dump())

    def _dump(self):
        self._assert_keychain_accessible()

        return self._run_command(
            ['security', 'dump-keychain', '-d', self._file]
        )

    def _parse(self, raw_dump_data):
        account = None
        capture_secret = False
        results = {}

        if not raw_dump_data:
            return {}

        for line in raw_dump_data:
            line = line.strip()

            regs = re.search(r'"svce"<blob>="([^"]+)"', line)
            if regs:
                account = regs.group(1)
                continue

            if line == 'data:' and account:
                capture_secret = True
                continue

            if capture_secret:
                results[account] = line.strip('"')

                # Reset for the next entry
                account = None
                capture_secret = False

        return results

    def _run_command(self, command):
        # print('Executing command: ' + ' '.join(command) + '\n',
        #       file=sys.stderr)

        try:
            result = subprocess.run(
                command, capture_output=True, text=True, check=True
            )
            return result.stdout.splitlines()
        except subprocess.CalledProcessError as e:
            raise StorageError(
                f'Error executing security command: {e}'
            ) from e
