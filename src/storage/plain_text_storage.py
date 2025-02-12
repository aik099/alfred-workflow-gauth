import os
import configparser

from storage.exceptions import StorageError


class PlainTextStorage:
    def __init__(self, config_file='~/.gauth'):
        self._config_file = config_file
        self._absolute_storage_path = os.path.expanduser(self._config_file)

        self._config = configparser.RawConfigParser()

        if not os.path.isfile(self._absolute_storage_path):
            raise StorageError(f'File "{config_file}" not found.')

        try:
            self._config.read(self._absolute_storage_path)
        except Exception as e:
            raise StorageError(f'File "{config_file}" syntax is invalid.') from e

        self._accounts = self._config.sections()

        if not self._accounts:
            raise StorageError(f'File "{config_file}" has no accounts.')

    def destroy(self):
        os.remove(self._absolute_storage_path)

    def get_file(self):
        return self._config_file

    def get_accounts(self):
        return self._accounts

    def get_secret(self, account):
        try:
            return self._config.get(account, 'secret')
        except:
            raise StorageError(f'Account "{account}" not found.')
