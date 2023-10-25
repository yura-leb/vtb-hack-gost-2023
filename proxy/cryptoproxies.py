from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
import gostcrypto
from BaseCryptoSystem import BaseCryptoSystem


class Cryptoproxy(BaseCryptoSystem):
    def __init__(self) -> None:
        super().__init__()
        self._keygen_admin()

    def _keygen_admin(self):
        right_password = b"super secret password"
        self.salt = get_random_bytes(16)
        self.key = PBKDF2(
            right_password, self.salt, 32, count=1000000, hmac_hash_module=SHA512
        )

    def verify_password(self, password: bytes) -> bool:
        return self.key == PBKDF2(
            password, self.salt, 32, count=1000000, hmac_hash_module=SHA512
        )


class CryptoGostproxy(BaseCryptoSystem):
    def __init__(self) -> None:
        super().__init__()
        self._keygen_admin()

    def _keygen_admin(self):
        right_password = b"super secret password"
        self.salt = get_random_bytes(32)
        pbkdf_obj = gostcrypto.gostpbkdf.new(
            right_password, salt=self.salt, counter=2000
        )
        self.key = pbkdf_obj.derive(32)

    def verify_password(self, password: bytes) -> bool:
        return self.key == gostcrypto.gostpbkdf.new(
            password, salt=self.salt, counter=2000
        ).derive(32)
