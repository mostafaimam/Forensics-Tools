r"""analysis_dpapi - decrypt Windows DPAPI blobs with supplied secrets.

The examiner supplies the secret - a user's logon password (+ SID), a
pre-computed SHA-1 password hash, or (planned) the domain DPAPI backup RSA
key.  Nothing is recovered by guessing.

* ``masterkey`` - decrypt a ``%APPDATA%\Microsoft\Protect\<SID>\<GUID>``
  master-key file (Win7+ SHA-512 / AES-256 scheme) and emit the 64-byte
  master key.
* ``blob`` - parse and decrypt a DPAPI data blob given the right master
  key (and optional entropy); verify the blob signature; recognise
  common blob types (browser ``os_crypt`` key, Credential Manager, Wi-Fi).
* ``scan`` - walk a ``Protect`` directory plus a folder of blobs, decrypt
  every master key the password unlocks, then every blob those keys cover.

Pure standard library, including a bundled AES-CBC implementation.
Read-only; IR-scoped.
"""

__version__ = "0.1.0"
