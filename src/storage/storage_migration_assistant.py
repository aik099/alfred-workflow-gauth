from storage.apple_keychain_storage import AppleKeychainStorage
from storage.exceptions import StorageError
from storage.plain_text_storage import PlainTextStorage


class StorageMigrationAssistant:
    def __init__(self, target_storage: AppleKeychainStorage):
        self._target_storage = target_storage

        try:
            self._source_storage = PlainTextStorage()
            self.can_migrate = True
        except StorageError:
            self.can_migrate = False

    def migrate(self):
        if not self.can_migrate:
            raise StorageError('No accounts to migrate.')

        added_accounts = []

        try:
            for account in self._source_storage.get_accounts():
                secret = self._source_storage.get_secret(account)

                if self._target_storage.add_account(account, secret):
                    added_accounts.append(account)

            self._source_storage.destroy()
        except StorageError as e:
            for account in added_accounts:
                self._target_storage.delete_account(account)

            raise e

        return len(added_accounts)

    def get_source_storage_file(self):
        return self._source_storage.get_file()
