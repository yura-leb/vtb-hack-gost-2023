import gostcrypto
import asyncio
import os
from Crypto.Signature import pss
from Crypto.Hash import (
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
)
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from gostcrypto.gostsignature.gost_34_10_2012 import GOST34102012
from typing import Any, Dict, Tuple

# metadata =
# {
#    sym: {
#        type: kuznechik/magma/aes,
#        mode: ECB, CBC, CFB, CTR, OFB,
#        pad_mode: PAD_MODE_1, PAD_MODE_2 (for ECB)
#       },
#    asym: {
#            hash: SHA224/SHA256/SHA384/SHA512/SHA3_224/SHA3_256/SHA3_384/SHA3_512
#            }
#    sign: {
#            type: gost/rsa
#            hash: SHA224/SHA256/SHA384/SHA512/SHA3_224/SHA3_256/SHA3_384/SHA3_512
#            param_set: A/B/C/D
#           }
# }

class BaseCryptoSystem:
    def __init__(self) -> None:
        self._sym_gost_modes = {
            "ECB": gostcrypto.gostcipher.MODE_ECB,
            "CBC": gostcrypto.gostcipher.MODE_CBC,
            "CFB": gostcrypto.gostcipher.MODE_CFB,
            "CTR": gostcrypto.gostcipher.MODE_CTR,
            "OFB": gostcrypto.gostcipher.MODE_OFB,
        }

        self._sym_aes_modes = {
            "ECB": AES.MODE_ECB,
            "CBC": AES.MODE_CBC,
            "CFB": AES.MODE_CFB,
            "CTR": AES.MODE_CTR,
            "OFB": AES.MODE_OFB,
        }

        self.init_vect_len = {
            "kuznechik": {"ECB": 0, "CBC": 16, "CFB": 16, "CTR": 8, "OFB": 16},
            "magma": {"ECB": 0, "CBC": 8, "CFB": 8, "CTR": 4, "OFB": 8},
            "aes": {
                "ECB": 0,
                "CBC": AES.block_size,
                "CFB": AES.block_size,
                "CTR": AES.block_size // 2,
                "OFB": AES.block_size,
            },
        }

        self._signer = dict()
        self._sign_private_key = dict()
        self._sign_public_key = dict()
        self._asym_encryptor = dict()
        self._asym_public_key = dict()

        self._rsa_hashes = {
            "SHA256": SHA256,
            "SHA224": SHA224,
            "SHA384": SHA384,
            "SHA512": SHA512,
            "SHA3_224": SHA3_224,
            "SHA3_256": SHA3_256,
            "SHA3_384": SHA3_384,
            "SHA3_512": SHA3_512,
        }

        self._sign_pad_modes = {
            "PAD_MODE_1": gostcrypto.gostcipher.PAD_MODE_1,
            "PAD_MODE_2": gostcrypto.gostcipher.PAD_MODE_2,
        }

        self._sign_gost_modes = {
            "256": gostcrypto.gostsignature.MODE_256,
            "512": gostcrypto.gostsignature.MODE_512,
        }

        self._sign_gost_size_curve = {
            "256": {
                "A": self._get_curve("256", "id-tc26-gost-3410-2012-256-paramSetA"),
                "B": self._get_curve("256", "id-tc26-gost-3410-2012-256-paramSetB"),
                "C": self._get_curve("256", "id-tc26-gost-3410-2012-256-paramSetC"),
                "D": self._get_curve("256", "id-tc26-gost-3410-2012-256-paramSetD"),
            },
            "512": {
                "A": self._get_curve("512", "id-tc26-gost-3410-12-512-paramSetA"),
                "B": self._get_curve("512", "id-tc26-gost-3410-12-512-paramSetB"),
                "C": self._get_curve("512", "id-tc26-gost-3410-2012-512-paramSetC"),
            },
        }

        self.asym_private_files = [
            f"keys/asym_rsa_{hash}_private.der" for hash in self._rsa_hashes
        ]
        self.asym_public_files = [
            f"keys/asym_rsa_{hash}_public.der" for hash in self._rsa_hashes
        ]
        self.sign_rsa_files = ["keys/sign_rsa_private.der", "keys/sign_rsa_public.der"]

        self.size_params = [
            ("256", "A"),
            ("256", "B"),
            ("256", "C"),
            ("256", "D"),
            ("512", "A"),
            ("512", "B"),
            ("512", "C"),
        ]
        self.sign_private_gost_files = [
            f"keys/sign_gost_{size}_{param}_private.der"
            for size, param in self.size_params
        ]
        self.sign_public_gost_files = [
            f"keys/sign_gost_{size}_{param}_public.der"
            for size, param in self.size_params
        ]

        self._init_asym_keys()
        return

    def _get_curve(self, sign_mode: str, curve_type: str) -> GOST34102012:
        return gostcrypto.gostsignature.GOST34102012(
            self._sign_gost_modes[sign_mode],
            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[curve_type],
        )

    def all_files_exist(self) -> bool:
        return (
            all(map(os.path.isfile, self.sign_rsa_files))
            and all(map(os.path.isfile, self.asym_public_files))
            and all(map(os.path.isfile, self.asym_private_files))
            and all(map(os.path.isfile, self.sign_public_gost_files))
            and all(map(os.path.isfile, self.sign_private_gost_files))
        )

    def _init_asym_keys(self) -> None:
        if not self.all_files_exist():
            try:
                os.mkdir("keys")
            except FileExistsError:
                pass
            self._keygen_asym()

        for hash in self._rsa_hashes:
            with open(f"keys/asym_rsa_{hash}_private.der", "rb") as key_file:
                self._asym_encryptor[hash] = PKCS1_OAEP.new(
                    RSA.import_key(key_file.read()), self._rsa_hashes[hash]
                )
            with open(f"keys/asym_rsa_{hash}_public.der", "rb") as key_file:
                self._asym_public_key[hash] = RSA.import_key(
                    key_file.read()
                ).export_key()

        with open("keys/sign_rsa_private.der", "rb") as key_file:
            self._signer["rsa"] = RSA.import_key(key_file.read())

        with open("keys/sign_rsa_public.der", "rb") as key_file:
            self._sign_public_key["rsa"] = RSA.import_key(key_file.read()).export_key()
        self._init_gost_sign()

    def _init_gost_sign(self) -> None:
        self._signer["gost"] = dict()
        self._signer["gost"]["256"] = self._sign_gost_size_curve["256"]
        self._signer["gost"]["512"] = self._sign_gost_size_curve["512"]
        self._sign_private_key["gost"] = dict()
        self._sign_private_key["gost"]["256"] = dict()
        self._sign_private_key["gost"]["512"] = dict()
        self._sign_public_key["gost"] = dict()
        self._sign_public_key["gost"]["256"] = dict()
        self._sign_public_key["gost"]["512"] = dict()

        for priv_file, pub_file, (size, param_set) in zip(
            self.sign_private_gost_files, self.sign_public_gost_files, self.size_params
        ):
            with open(priv_file, "rb") as key_file:
                self._sign_private_key["gost"][size][param_set] = bytearray(
                    key_file.read()
                )

            with open(pub_file, "rb") as key_file:
                self._sign_public_key["gost"][size][param_set] = key_file.read()

    def _keygen_asym(self) -> None:
        self._keygen_rsa()
        self._signer["gost"] = dict()
        self._signer["gost"]["256"] = self._sign_gost_size_curve["256"]
        self._signer["gost"]["512"] = self._sign_gost_size_curve["512"]
        self._keygen_sign_gost()

    def _keygen_rsa(self) -> None:
        for hash in self._rsa_hashes.keys():
            private, public = (
                f"keys/asym_rsa_{hash}_private.der",
                f"keys/asym_rsa_{hash}_public.der",
            )

            private_key = RSA.generate(2048)
            public_key = private_key.publickey()

            with open(private, "wb") as prv_file:
                prv_file.write(private_key.export_key())
            with open(public, "wb") as pub_file:
                pub_file.write(public_key.export_key())

        private, public = self.sign_rsa_files

        private_key = RSA.generate(2048)
        public_key = private_key.publickey()

        with open(private, "wb") as prv_file:
            prv_file.write(private_key.export_key())
        with open(public, "wb") as pub_file:
            pub_file.write(public_key.export_key())

    def _public_sign_key_generate(
        self, private_key: bytearray, sign_size: str = "256", sign_param_set: str = "A"
    ) -> bytes:
        return bytes(
            self._signer["gost"][sign_size][sign_param_set].public_key_generate(
                private_key
            )
        )

    def _keygen_sign_gost(self) -> None:
        for priv_file, pub_file, (sign_size, sign_param_set) in zip(
            self.sign_private_gost_files, self.sign_public_gost_files, self.size_params
        ):
            private_key = Random.get_random_bytes(int(sign_size) // 8)
            public_key = self._public_sign_key_generate(
                private_key, sign_size, sign_param_set
            )

            with open(priv_file, "wb") as private_file:
                private_file.write(private_key)

            with open(pub_file, "wb") as public_file:
                public_file.write(public_key)

    def _get_sym_type(
        self,
        sym_key: bytearray,
        sym_params: dict,
        init_vect: bytes = b"",
    ) -> Any:
        sym_type = sym_params["type"]
        sym_mode = sym_params["mode"]
        sym_pad_mode = sym_params["pad_mode"]

        if sym_mode == "ECB":
            if sym_type in {"kuznechik", "magma"}:
                return gostcrypto.gostcipher.new(
                    sym_type,
                    sym_key,
                    self._sym_gost_modes[sym_mode],
                    pad_mode=self._sign_pad_modes[sym_pad_mode],
                )
            elif sym_type == "aes":
                return AES.new(sym_key, AES.MODE_ECB)
        else:
            if sym_mode in {"CTR", "CFB", "OFB"}:
                if sym_type in {"kuznechik", "magma"}:
                    return gostcrypto.gostcipher.new(
                        sym_type,
                        sym_key,
                        self._sym_gost_modes[sym_mode],
                        init_vect=init_vect,
                    )
                elif sym_type == "aes":
                    if sym_mode == "CTR":
                        return AES.new(
                            sym_key,
                            self._sym_aes_modes[sym_mode],
                            nonce=init_vect,
                        )
                    else:
                        return AES.new(
                            sym_key, self._sym_aes_modes[sym_mode], iv=init_vect
                        )

            elif sym_mode == "CBC":
                if sym_type in {"kuznechik", "magma"}:
                    return gostcrypto.gostcipher.new(
                        sym_type,
                        sym_key,
                        self._sym_gost_modes[sym_mode],
                        init_vect=init_vect,
                        pad_mode=self._sign_pad_modes[sym_pad_mode],
                    )
                elif sym_type == "aes":
                    return AES.new(sym_key, self._sym_aes_modes[sym_mode], iv=init_vect)
            else:
                raise Exception("Wrong symmetric cipher")

    def _keygen_sym(self) -> bytearray:
        return bytearray(Random.get_random_bytes(32))

    def _sym_encrypt(
        self,
        data: bytearray,
        sym_key: bytearray,
        sym_params: dict,
    ) -> Tuple[bytes, bytes]:
        init_vect = Random.get_random_bytes(
            self.init_vect_len[sym_params["type"]][sym_params["mode"]]
        )

        sym_obj = self._get_sym_type(sym_key, sym_params, init_vect)

        if sym_params["type"] == "aes":
            padded_data = pad(bytes(data), AES.block_size)
            return (sym_obj.encrypt(padded_data), init_vect)
        return (bytes(sym_obj.encrypt(data)), init_vect)

    def _unpad(self, data: bytearray) -> bytearray:
        return data.rstrip(b"\x00").rstrip(b"\x80")

    def _sym_decrypt(
        self,
        ciphertext: bytes,
        sym_key: bytearray,
        sym_params: dict,
        init_vect: bytes = b"",
    ) -> bytearray:
        sym_obj = self._get_sym_type(sym_key, sym_params, init_vect)
        if sym_params["type"] == "aes":
            return bytearray(unpad(sym_obj.decrypt(ciphertext), AES.block_size))

        return self._unpad(sym_obj.decrypt(bytearray(ciphertext)))

    def _sign(
        self,
        data: bytearray,
        sign_params: dict,
    ) -> bytes:
        if sign_params["type"] == "gost":
            sign_size, sign_param_set, sign_hash = (
                sign_params["hash"][-3:],
                sign_params["param_set"],
                sign_params["hash"],
            )
            return bytes(
                self._signer["gost"][sign_size][sign_param_set].sign(
                    self._sign_private_key["gost"][sign_size][sign_param_set],
                    gostcrypto.gosthash.GOST34112012(sign_hash, data).digest(),
                )
            )
        sign_hash = sign_params["hash"]
        h = self._rsa_hashes[sign_hash].new(bytes(data))
        return pss.new(self._signer["rsa"]).sign(h)

    def _verify(
        self,
        public_sign_key: bytes,
        data: bytearray,
        signature: bytes,
        sign_params: dict,
    ) -> bool:
        if sign_params["type"] == "gost":
            sign_size, sign_param_set, sign_hash = (
                sign_params["hash"][-3:],
                sign_params["param_set"],
                sign_params["hash"],
            )
            return self._signer["gost"][sign_size][sign_param_set].verify(
                bytearray(public_sign_key),
                gostcrypto.gosthash.GOST34112012(sign_hash, data).digest(),
                bytearray(signature),
            )

        sign_hash = sign_params["hash"]
        h = self._rsa_hashes[sign_hash].new(data)
        verifier = pss.new(RSA.importKey(public_sign_key))
        try:
            verifier.verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    def _parse_metadata(
        self, metadata: dict
    ) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
        sym_params = metadata["sym"]
        asym_params = metadata["asym"]
        sign_params = metadata["sign"]
        return sym_params, asym_params, sign_params

    def get_asym_public_key(self, metadata: dict) -> bytes:
        return self._asym_public_key[metadata["asym"]["hash"]]

    def get_sign_public_key(self, metadata: dict) -> bytes:
        if metadata["sign"]["type"] == "gost":
            sign_size = metadata["sign"]["hash"][-3:]
            sign_param_set = metadata["sign"]["param_set"]
            return self._sign_public_key["gost"][sign_size][sign_param_set]
        else:
            return self._sign_public_key["rsa"]

    def asym_encrypt(
        self, data: bytes, public_asym_key: bytes, asym_params: dict
    ) -> bytes:
        cipher_rsa = PKCS1_OAEP.new(
            RSA.import_key(public_asym_key), self._rsa_hashes[asym_params["hash"]]
        )
        return cipher_rsa.encrypt(data)

    def asym_decrypt(self, ciphertext: bytes, asym_params: dict) -> bytes:
        return self._asym_encryptor[asym_params["hash"]].decrypt(ciphertext)

    def encrypt_all(
        self, data: bytearray, public_key: bytes, metadata: dict
    ) -> Tuple[bytes, bytes, bytes, bytes]:
        sym_params, asym_params, sign_params = self._parse_metadata(metadata)

        sym_key = self._keygen_sym()
        signature = self._sign(data, sign_params)
        encrypted_message, iv = self._sym_encrypt(data, sym_key, sym_params)
        encrypted_sym_key = self.asym_encrypt(bytes(sym_key), public_key, asym_params)
        return encrypted_message, encrypted_sym_key, signature, iv

    def decrypt_check(
        self,
        ciphertext: bytes,
        encrypted_sym_key: bytes,
        public_sign_key: bytes,
        signature: bytes,
        metadata: dict,
        init_vect: bytes,
    ) -> Tuple[bytearray, bool]:
        sym_params, asym_params, sign_params = self._parse_metadata(metadata)

        sym_key = self.asym_decrypt(encrypted_sym_key, asym_params)
        data = self._sym_decrypt(ciphertext, sym_key, sym_params, init_vect)
        return data, self._verify(
            public_sign_key,
            data,
            signature,
            sign_params,
        )
