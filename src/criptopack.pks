CREATE OR REPLACE PACKAGE criptopack AS
  /**
   * @author Daniel Madeira
  * @version 1.1
   * @date 2026-10-21
   * @brief Descreve a API pública da package de hashes, CRC e criptografia AES.
   *
   * Disponibiliza MD5, SHA-1, SHA-256, SHA3-224, SHA3-256, SHA3-384,
   * SHA3-512, SHA-384, SHA-512 e CRC-32 para VARCHAR2, CLOB, BLOB e NUMBER.
  * Expõe cifragem e decifragem AES-128, AES-192 e AES-256 em CBC com
  * padding PKCS#7, além de variantes autenticadas com HMAC-SHA-256.
  * Texto usa UTF-8; hashes e ciphertexts textuais são hexadecimais,
  * enquanto os dados binários permanecem binários.
   *
  * AES exige chave de 16, 24 ou 32 bytes, conforme a variante, e IV CBC
  * de 16 bytes. CBC legado não autentica dados; prefira os métodos com
  * sufixo _autenticado, que verificam HMAC antes da decifragem.
   * Os hashes rápidos desta package não substituem KDF para senhas.
   *
   * @return Declarações públicas disponíveis em criptopack.
   *
   * @license GPL-3.0-only
   * This program is free software: you can redistribute it and/or modify
   * it under the terms of the GNU General Public License as published by
   * the Free Software Foundation, either version 3 of the License, or
   * (at your option) any later version.
   *
   * This program is distributed in the hope that it will be useful,
   * but WITHOUT ANY WARRANTY; without even the implied warranty of
   * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   * GNU General Public License for more details.
   *
   * You should have received a copy of the GNU General Public License
   * along with this program. If not, see <https://gnu.org>.
   */

  /** @brief Calcula o MD5 dos bytes UTF-8 do texto.
   * @param p_texto Texto a ser resumido.
   * @return Digest hexadecimal minúsculo de 32 caracteres.
   */
  FUNCTION hash_md5(p_texto IN VARCHAR2) RETURN VARCHAR2;

  /** @brief Calcula o MD5 do conteúdo textual do CLOB convertido para UTF-8.
   * @param p_texto CLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 32 caracteres.
   */
  FUNCTION hash_md5(p_texto IN CLOB) RETURN VARCHAR2;

  /** @brief Calcula o MD5 dos bytes do BLOB.
   * @param p_texto BLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 32 caracteres.
   */
  FUNCTION hash_md5(p_texto IN BLOB) RETURN VARCHAR2;

  /** @brief Calcula o MD5 da representação decimal TM9 do número.
   * @param p_numero Número a ser resumido.
   * @return Digest hexadecimal minúsculo de 32 caracteres.
   */
  FUNCTION hash_md5(p_numero IN NUMBER) RETURN VARCHAR2;

  /** @brief Calcula SHA-1 dos bytes UTF-8 do texto.
   * @param p_texto Texto a ser resumido.
   * @return Digest hexadecimal minúsculo de 40 caracteres.
   */
  FUNCTION hash_sha1(p_texto IN VARCHAR2) RETURN VARCHAR2;

  /** @brief Calcula SHA-1 do CLOB convertido para UTF-8.
   * @param p_texto CLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 40 caracteres.
   */
  FUNCTION hash_sha1(p_texto IN CLOB) RETURN VARCHAR2;

  /** @brief Calcula SHA-1 dos bytes do BLOB.
   * @param p_texto BLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 40 caracteres.
   */
  FUNCTION hash_sha1(p_texto IN BLOB) RETURN VARCHAR2;

  /** @brief Calcula SHA-1 da representação decimal TM9 do número.
   * @param p_numero Número a ser resumido.
   * @return Digest hexadecimal minúsculo de 40 caracteres.
   */
  FUNCTION hash_sha1(p_numero IN NUMBER) RETURN VARCHAR2;

  /** @brief Calcula SHA-256 dos bytes UTF-8 do texto.
   * @param p_texto Texto a ser resumido.
   * @return Digest hexadecimal minúsculo de 64 caracteres.
   */
  FUNCTION hash_sha256(p_texto IN VARCHAR2) RETURN VARCHAR2;

  /** @brief Calcula SHA-256 do CLOB convertido para UTF-8.
   * @param p_texto CLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 64 caracteres.
   */
  FUNCTION hash_sha256(p_texto IN CLOB) RETURN VARCHAR2;

  /** @brief Calcula SHA-256 dos bytes do BLOB.
   * @param p_texto BLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 64 caracteres.
   */
  FUNCTION hash_sha256(p_texto IN BLOB) RETURN VARCHAR2;

  /** @brief Calcula SHA-256 da representação decimal TM9 do número.
   * @param p_numero Número a ser resumido.
   * @return Digest hexadecimal minúsculo de 64 caracteres.
   */
  FUNCTION hash_sha256(p_numero IN NUMBER) RETURN VARCHAR2;

  /** @brief Calcula SHA3-224 dos bytes UTF-8 do texto.
   * @param p_texto Texto a ser resumido.
   * @return Digest hexadecimal minúsculo de 56 caracteres.
   */
  FUNCTION hash_sha3_224(p_texto IN VARCHAR2) RETURN VARCHAR2;

  /** @brief Calcula SHA3-224 do CLOB convertido para UTF-8.
   * @param p_texto CLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 56 caracteres.
   */
  FUNCTION hash_sha3_224(p_texto IN CLOB) RETURN VARCHAR2;

  /** @brief Calcula SHA3-224 dos bytes do BLOB.
   * @param p_texto BLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 56 caracteres.
   */
  FUNCTION hash_sha3_224(p_texto IN BLOB) RETURN VARCHAR2;

  /** @brief Calcula SHA3-224 da representação decimal TM9 do número.
   * @param p_numero Número a ser resumido.
   * @return Digest hexadecimal minúsculo de 56 caracteres.
   */
  FUNCTION hash_sha3_224(p_numero IN NUMBER) RETURN VARCHAR2;

  /** @brief Calcula SHA3-256 dos bytes UTF-8 do texto.
   * @param p_texto Texto a ser resumido.
   * @return Digest hexadecimal minúsculo de 64 caracteres.
   */
  FUNCTION hash_sha3_256(p_texto IN VARCHAR2) RETURN VARCHAR2;

  /** @brief Calcula SHA3-256 do CLOB convertido para UTF-8.
   * @param p_texto CLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 64 caracteres.
   */
  FUNCTION hash_sha3_256(p_texto IN CLOB) RETURN VARCHAR2;

  /** @brief Calcula SHA3-256 dos bytes do BLOB.
   * @param p_texto BLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 64 caracteres.
   */
  FUNCTION hash_sha3_256(p_texto IN BLOB) RETURN VARCHAR2;

  /** @brief Calcula SHA3-256 da representação decimal TM9 do número.
   * @param p_numero Número a ser resumido.
   * @return Digest hexadecimal minúsculo de 64 caracteres.
   */
  FUNCTION hash_sha3_256(p_numero IN NUMBER) RETURN VARCHAR2;

  /** @brief Calcula SHA3-384 dos bytes UTF-8 do texto.
   * @param p_texto Texto a ser resumido.
   * @return Digest hexadecimal minúsculo de 96 caracteres.
   */
  FUNCTION hash_sha3_384(p_texto IN VARCHAR2) RETURN VARCHAR2;

  /** @brief Calcula SHA3-384 do CLOB convertido para UTF-8.
   * @param p_texto CLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 96 caracteres.
   */
  FUNCTION hash_sha3_384(p_texto IN CLOB) RETURN VARCHAR2;

  /** @brief Calcula SHA3-384 dos bytes do BLOB.
   * @param p_texto BLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 96 caracteres.
   */
  FUNCTION hash_sha3_384(p_texto IN BLOB) RETURN VARCHAR2;

  /** @brief Calcula SHA3-384 da representação decimal TM9 do número.
   * @param p_numero Número a ser resumido.
   * @return Digest hexadecimal minúsculo de 96 caracteres.
   */
  FUNCTION hash_sha3_384(p_numero IN NUMBER) RETURN VARCHAR2;

  /** @brief Calcula SHA3-512 dos bytes UTF-8 do texto.
   * @param p_texto Texto a ser resumido.
   * @return Digest hexadecimal minúsculo de 128 caracteres.
   */
  FUNCTION hash_sha3_512(p_texto IN VARCHAR2) RETURN VARCHAR2;

  /** @brief Calcula SHA3-512 do CLOB convertido para UTF-8.
   * @param p_texto CLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 128 caracteres.
   */
  FUNCTION hash_sha3_512(p_texto IN CLOB) RETURN VARCHAR2;

  /** @brief Calcula SHA3-512 dos bytes do BLOB.
   * @param p_texto BLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 128 caracteres.
   */
  FUNCTION hash_sha3_512(p_texto IN BLOB) RETURN VARCHAR2;

  /** @brief Calcula SHA3-512 da representação decimal TM9 do número.
   * @param p_numero Número a ser resumido.
   * @return Digest hexadecimal minúsculo de 128 caracteres.
   */
  FUNCTION hash_sha3_512(p_numero IN NUMBER) RETURN VARCHAR2;

  /** @brief Calcula SHA-384 dos bytes UTF-8 do texto.
   * @param p_texto Texto a ser resumido.
   * @return Digest hexadecimal minúsculo de 96 caracteres.
   */
  FUNCTION hash_sha384(p_texto IN VARCHAR2) RETURN VARCHAR2;

  /** @brief Calcula SHA-384 do CLOB convertido para UTF-8.
   * @param p_texto CLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 96 caracteres.
   */
  FUNCTION hash_sha384(p_texto IN CLOB) RETURN VARCHAR2;

  /** @brief Calcula SHA-384 dos bytes do BLOB.
   * @param p_texto BLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 96 caracteres.
   */
  FUNCTION hash_sha384(p_texto IN BLOB) RETURN VARCHAR2;

  /** @brief Calcula SHA-384 da representação decimal TM9 do número.
   * @param p_numero Número a ser resumido.
   * @return Digest hexadecimal minúsculo de 96 caracteres.
   */
  FUNCTION hash_sha384(p_numero IN NUMBER) RETURN VARCHAR2;

  /** @brief Calcula SHA-512 dos bytes UTF-8 do texto.
   * @param p_texto Texto a ser resumido.
   * @return Digest hexadecimal minúsculo de 128 caracteres.
   */
  FUNCTION hash_sha512(p_texto IN VARCHAR2) RETURN VARCHAR2;

  /** @brief Calcula SHA-512 do CLOB convertido para UTF-8.
   * @param p_texto CLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 128 caracteres.
   */
  FUNCTION hash_sha512(p_texto IN CLOB) RETURN VARCHAR2;

  /** @brief Calcula SHA-512 dos bytes do BLOB.
   * @param p_texto BLOB a ser resumido.
   * @return Digest hexadecimal minúsculo de 128 caracteres.
   */
  FUNCTION hash_sha512(p_texto IN BLOB) RETURN VARCHAR2;

  /** @brief Calcula SHA-512 da representação decimal TM9 do número.
   * @param p_numero Número a ser resumido.
   * @return Digest hexadecimal minúsculo de 128 caracteres.
   */
  FUNCTION hash_sha512(p_numero IN NUMBER) RETURN VARCHAR2;

  /** @brief Calcula CRC-32/ISO-HDLC do texto codificado em UTF-8.
   * @param p_texto Texto de entrada.
   * @return CRC hexadecimal minúsculo de 8 caracteres.
   */
  FUNCTION hash_crc32(p_texto IN VARCHAR2) RETURN VARCHAR2;

  /** @brief Calcula CRC-32/ISO-HDLC do CLOB convertido para UTF-8.
   * @param p_texto CLOB de entrada.
   * @return CRC hexadecimal minúsculo de 8 caracteres.
   */
  FUNCTION hash_crc32(p_texto IN CLOB) RETURN VARCHAR2;

  /** @brief Calcula CRC-32/ISO-HDLC dos bytes do BLOB.
   * @param p_texto BLOB de entrada.
   * @return CRC hexadecimal minúsculo de 8 caracteres.
   */
  FUNCTION hash_crc32(p_texto IN BLOB) RETURN VARCHAR2;

  /** @brief Calcula CRC-32/ISO-HDLC da representação decimal TM9.
   * @param p_numero Número de entrada.
   * @return CRC hexadecimal minúsculo de 8 caracteres.
   */
  FUNCTION hash_crc32(p_numero IN NUMBER) RETURN VARCHAR2;

  /** @brief Criptografa texto com AES-128-CBC e padding PKCS#7; codifica o ciphertext em hexadecimal.
    * @param p_texto_varchar2 Texto em UTF-8.
   * @param p_chave Chave com exatamente 16 bytes UTF-8.
   * @param p_iv Vetor de inicialização com exatamente 16 bytes UTF-8, único e imprevisível por operação.
    * @return Ciphertext hexadecimal em VARCHAR2.
   */
  FUNCTION cripto_aes128(p_texto_varchar2 IN VARCHAR2, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN VARCHAR2;

  /** @brief Criptografa CLOB com AES-128-CBC/PKCS#7 e retorna ciphertext hexadecimal.
    * @param p_texto_clob Texto de entrada.
   * @param p_chave Chave com exatamente 16 bytes UTF-8.
   * @param p_iv IV com exatamente 16 bytes UTF-8, único e imprevisível por operação.
   * @return Ciphertext hexadecimal em CLOB.
   */
  FUNCTION cripto_aes128(p_texto_clob IN CLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN CLOB;

  /** @brief Criptografa bytes de BLOB com AES-128-CBC/PKCS#7.
    * @param p_texto_blob Dados binários de entrada.
   * @param p_chave Chave com exatamente 16 bytes UTF-8.
   * @param p_iv IV com exatamente 16 bytes UTF-8, único e imprevisível por operação.
   * @return Ciphertext binário em BLOB.
   */
  FUNCTION cripto_aes128(p_texto_blob IN BLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN BLOB;

  /** @brief Criptografa a representação decimal TM9 de NUMBER com AES-128-CBC/PKCS#7.
   * @param p_numero Número de entrada.
   * @param p_chave Chave com exatamente 16 bytes UTF-8.
   * @param p_iv IV com exatamente 16 bytes UTF-8, único e imprevisível por operação.
   * @return Ciphertext hexadecimal em VARCHAR2.
   */
  FUNCTION cripto_aes128(p_numero IN NUMBER, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN VARCHAR2;

  /** @brief Criptografa bytes RAW com AES-128-CBC/PKCS#7.
    * @param p_texto_raw Dados binários de entrada.
   * @param p_chave Chave com exatamente 16 bytes UTF-8.
   * @param p_iv IV com exatamente 16 bytes UTF-8, único e imprevisível por operação.
   * @return Ciphertext binário em RAW.
   */
  FUNCTION cripto_aes128(p_texto_raw IN RAW, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN RAW;

  /** @brief Descriptografa ciphertext hexadecimal AES-128-CBC/PKCS#7.
    * @param p_cifra_varchar2 Ciphertext hexadecimal.
   * @param p_chave Chave de 16 bytes UTF-8 correspondente.
   * @param p_iv IV de 16 bytes UTF-8 usado na cifragem.
  * @param p_tipo VARCHAR2 ou NUMBER; NUMBER valida e retorna a representação decimal descriptografada como texto.
   * @return Texto descriptografado em VARCHAR2.
   */
  FUNCTION descripto_aes128(p_cifra_varchar2 IN VARCHAR2, p_chave IN VARCHAR2, p_iv IN VARCHAR2, p_tipo IN VARCHAR2 DEFAULT 'VARCHAR2') RETURN VARCHAR2;

  /** @brief Descriptografa ciphertext hexadecimal AES-128-CBC/PKCS#7 para CLOB.
    * @param p_cifra_clob Ciphertext hexadecimal em CLOB.
   * @param p_chave Chave de 16 bytes UTF-8 correspondente.
   * @param p_iv IV de 16 bytes UTF-8 usado na cifragem.
  * @param p_tipo VARCHAR2 ou NUMBER; NUMBER valida e retorna a representação decimal descriptografada como texto.
   * @return Texto descriptografado em CLOB.
   */
  FUNCTION descripto_aes128(p_cifra_clob IN CLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2, p_tipo IN VARCHAR2 DEFAULT 'VARCHAR2') RETURN CLOB;

  /** @brief Descriptografa BLOB cifrado com AES-128-CBC/PKCS#7.
    * @param p_cifra_blob Ciphertext binário.
   * @param p_chave Chave de 16 bytes UTF-8 correspondente.
   * @param p_iv IV de 16 bytes UTF-8 usado na cifragem.
   * @return Dados descriptografados em BLOB.
   */
  FUNCTION descripto_aes128(p_cifra_blob IN BLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN BLOB;

  /** @brief Descriptografa RAW cifrado com AES-128-CBC/PKCS#7.
    * @param p_cifra_raw Ciphertext binário.
   * @param p_chave Chave de 16 bytes UTF-8 correspondente.
   * @param p_iv IV de 16 bytes UTF-8 usado na cifragem.
   * @return Dados descriptografados em RAW.
   */
  FUNCTION descripto_aes128(p_cifra_raw IN RAW, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN RAW;

  /** @brief Criptografa texto UTF-8 com AES-192-CBC/PKCS#7 e retorna hexadecimal.
    * @param p_texto_varchar2 Texto de entrada.
   * @param p_chave Chave com exatamente 24 bytes UTF-8.
   * @param p_iv IV com 16 bytes UTF-8, único e imprevisível por operação.
   * @return Ciphertext hexadecimal em VARCHAR2.
   */
  FUNCTION cripto_aes192(p_texto_varchar2 IN VARCHAR2, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN VARCHAR2;

  /** @brief Criptografa CLOB com AES-192-CBC/PKCS#7 e retorna hexadecimal.
    * @param p_texto_clob CLOB de entrada.
   * @param p_chave Chave com exatamente 24 bytes UTF-8.
   * @param p_iv IV com 16 bytes UTF-8, único e imprevisível por operação.
   * @return Ciphertext hexadecimal em CLOB.
   */
  FUNCTION cripto_aes192(p_texto_clob IN CLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN CLOB;

  /** @brief Criptografa bytes de BLOB com AES-192-CBC/PKCS#7.
    * @param p_texto_blob Dados binários de entrada.
   * @param p_chave Chave com exatamente 24 bytes UTF-8.
   * @param p_iv IV com 16 bytes UTF-8, único e imprevisível por operação.
   * @return Ciphertext binário em BLOB.
   */
  FUNCTION cripto_aes192(p_texto_blob IN BLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN BLOB;

  /** @brief Criptografa a representação TM9 de NUMBER com AES-192-CBC/PKCS#7.
   * @param p_numero Número de entrada.
   * @param p_chave Chave com exatamente 24 bytes UTF-8.
   * @param p_iv IV com 16 bytes UTF-8, único e imprevisível por operação.
   * @return Ciphertext hexadecimal em VARCHAR2.
   */
  FUNCTION cripto_aes192(p_numero IN NUMBER, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN VARCHAR2;

  /** @brief Criptografa bytes RAW com AES-192-CBC/PKCS#7.
    * @param p_texto_raw Dados binários de entrada.
   * @param p_chave Chave com exatamente 24 bytes UTF-8.
   * @param p_iv IV com 16 bytes UTF-8, único e imprevisível por operação.
   * @return Ciphertext binário em RAW.
   */
  FUNCTION cripto_aes192(p_texto_raw IN RAW, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN RAW;

  /** @brief Descriptografa texto hexadecimal AES-192-CBC/PKCS#7.
    * @param p_cifra_varchar2 Ciphertext hexadecimal.
   * @param p_chave Chave de 24 bytes UTF-8 correspondente.
   * @param p_iv IV de 16 bytes UTF-8 da cifragem.
  * @param p_tipo VARCHAR2 ou NUMBER; NUMBER valida e devolve a representação decimal descriptografada como texto.
   * @return Texto descriptografado em VARCHAR2.
   */
  FUNCTION descripto_aes192(p_cifra_varchar2 IN VARCHAR2, p_chave IN VARCHAR2, p_iv IN VARCHAR2, p_tipo IN VARCHAR2 DEFAULT 'VARCHAR2') RETURN VARCHAR2;

  /** @brief Descriptografa texto hexadecimal AES-192-CBC/PKCS#7 para CLOB.
    * @param p_cifra_clob Ciphertext hexadecimal em CLOB.
   * @param p_chave Chave de 24 bytes UTF-8 correspondente.
   * @param p_iv IV de 16 bytes UTF-8 da cifragem.
  * @param p_tipo VARCHAR2 ou NUMBER; NUMBER valida e retorna a representação decimal descriptografada como texto.
   * @return Texto descriptografado em CLOB.
   */
  FUNCTION descripto_aes192(p_cifra_clob IN CLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2, p_tipo IN VARCHAR2 DEFAULT 'VARCHAR2') RETURN CLOB;

  /** @brief Descriptografa BLOB AES-192-CBC/PKCS#7.
    * @param p_cifra_blob Ciphertext binário.
   * @param p_chave Chave de 24 bytes UTF-8 correspondente.
   * @param p_iv IV de 16 bytes UTF-8 da cifragem.
   * @return Dados descriptografados em BLOB.
   */
  FUNCTION descripto_aes192(p_cifra_blob IN BLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN BLOB;

  /** @brief Descriptografa RAW AES-192-CBC/PKCS#7.
    * @param p_cifra_raw Ciphertext binário.
   * @param p_chave Chave de 24 bytes UTF-8 correspondente.
   * @param p_iv IV de 16 bytes UTF-8 da cifragem.
   * @return Dados descriptografados em RAW.
   */
  FUNCTION descripto_aes192(p_cifra_raw IN RAW, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN RAW;

  /** @brief Criptografa texto UTF-8 com AES-256-CBC/PKCS#7 e retorna hexadecimal.
    * @param p_texto_varchar2 Texto de entrada.
   * @param p_chave Chave com exatamente 32 bytes UTF-8.
   * @param p_iv IV com 16 bytes UTF-8, único e imprevisível por operação.
   * @return Ciphertext hexadecimal em VARCHAR2.
   */
  FUNCTION cripto_aes256(p_texto_varchar2 IN VARCHAR2, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN VARCHAR2;

  /** @brief Criptografa CLOB com AES-256-CBC/PKCS#7 e retorna hexadecimal.
    * @param p_texto_clob CLOB de entrada.
   * @param p_chave Chave com exatamente 32 bytes UTF-8.
   * @param p_iv IV com 16 bytes UTF-8, único e imprevisível por operação.
   * @return Ciphertext hexadecimal em CLOB.
   */
  FUNCTION cripto_aes256(p_texto_clob IN CLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN CLOB;

  /** @brief Criptografa bytes BLOB com AES-256-CBC/PKCS#7.
    * @param p_texto_blob Dados binários de entrada.
   * @param p_chave Chave com exatamente 32 bytes UTF-8.
   * @param p_iv IV com 16 bytes UTF-8, único e imprevisível por operação.
   * @return Ciphertext binário em BLOB.
   */
  FUNCTION cripto_aes256(p_texto_blob IN BLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN BLOB;

  /** @brief Criptografa a representação TM9 de NUMBER com AES-256-CBC/PKCS#7.
   * @param p_numero Número de entrada.
   * @param p_chave Chave com exatamente 32 bytes UTF-8.
   * @param p_iv IV com 16 bytes UTF-8, único e imprevisível por operação.
   * @return Ciphertext hexadecimal em VARCHAR2.
   */
  FUNCTION cripto_aes256(p_numero IN NUMBER, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN VARCHAR2;

  /** @brief Criptografa bytes RAW com AES-256-CBC/PKCS#7.
    * @param p_texto_raw Dados binários de entrada.
   * @param p_chave Chave com exatamente 32 bytes UTF-8.
   * @param p_iv IV com 16 bytes UTF-8, único e imprevisível por operação.
   * @return Ciphertext binário em RAW.
   */
  FUNCTION cripto_aes256(p_texto_raw IN RAW, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN RAW;

  /** @brief Descriptografa ciphertext hexadecimal AES-256-CBC/PKCS#7.
    * @param p_cifra_varchar2 Ciphertext hexadecimal.
   * @param p_chave Chave de 32 bytes UTF-8 correspondente.
   * @param p_iv IV de 16 bytes UTF-8 da cifragem.
  * @param p_tipo VARCHAR2 ou NUMBER; NUMBER valida e devolve a representação decimal descriptografada como texto.
   * @return Texto descriptografado em VARCHAR2.
   */
  FUNCTION descripto_aes256(p_cifra_varchar2 IN VARCHAR2, p_chave IN VARCHAR2, p_iv IN VARCHAR2, p_tipo IN VARCHAR2 DEFAULT 'VARCHAR2') RETURN VARCHAR2;

  /** @brief Descriptografa ciphertext hexadecimal AES-256-CBC/PKCS#7 para CLOB.
    * @param p_cifra_clob Ciphertext hexadecimal em CLOB.
   * @param p_chave Chave de 32 bytes UTF-8 correspondente.
   * @param p_iv IV de 16 bytes UTF-8 da cifragem.
  * @param p_tipo VARCHAR2 ou NUMBER; NUMBER valida e retorna a representação decimal descriptografada como texto.
   * @return Texto descriptografado em CLOB.
   */
  FUNCTION descripto_aes256(p_cifra_clob IN CLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2, p_tipo IN VARCHAR2 DEFAULT 'VARCHAR2') RETURN CLOB;

  /** @brief Descriptografa BLOB AES-256-CBC/PKCS#7.
    * @param p_cifra_blob Ciphertext binário.
   * @param p_chave Chave de 32 bytes UTF-8 correspondente.
   * @param p_iv IV de 16 bytes UTF-8 da cifragem.
   * @return Dados descriptografados em BLOB.
   */
  FUNCTION descripto_aes256(p_cifra_blob IN BLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN BLOB;

  /** @brief Descriptografa RAW AES-256-CBC/PKCS#7.
    * @param p_cifra_raw Ciphertext binário.
   * @param p_chave Chave de 32 bytes UTF-8 correspondente.
   * @param p_iv IV de 16 bytes UTF-8 da cifragem.
   * @return Dados descriptografados em RAW.
   */
  FUNCTION descripto_aes256(p_cifra_raw IN RAW, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN RAW;

  /**
   * @brief Cifra texto em envelope AES-CBC autenticado com HMAC-SHA-256.
   * O envelope hexadecimal contém versão, IV, ciphertext e MAC; não requer
   * IV no deciframento. Use chave aleatória de entropia adequada.
   */
  FUNCTION cripto_aes128_autenticado(p_texto_varchar2 IN VARCHAR2, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN VARCHAR2;
  FUNCTION descripto_aes128_autenticado(p_envelope_varchar2 IN VARCHAR2, p_chave IN VARCHAR2) RETURN VARCHAR2;
  FUNCTION cripto_aes128_autenticado(p_texto_clob IN CLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN CLOB;
  FUNCTION descripto_aes128_autenticado(p_envelope_clob IN CLOB, p_chave IN VARCHAR2) RETURN CLOB;
  FUNCTION cripto_aes128_autenticado(p_texto_blob IN BLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN BLOB;
  FUNCTION descripto_aes128_autenticado(p_envelope_blob IN BLOB, p_chave IN VARCHAR2) RETURN BLOB;

  FUNCTION cripto_aes192_autenticado(p_texto_varchar2 IN VARCHAR2, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN VARCHAR2;
  FUNCTION descripto_aes192_autenticado(p_envelope_varchar2 IN VARCHAR2, p_chave IN VARCHAR2) RETURN VARCHAR2;
  FUNCTION cripto_aes192_autenticado(p_texto_clob IN CLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN CLOB;
  FUNCTION descripto_aes192_autenticado(p_envelope_clob IN CLOB, p_chave IN VARCHAR2) RETURN CLOB;
  FUNCTION cripto_aes192_autenticado(p_texto_blob IN BLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN BLOB;
  FUNCTION descripto_aes192_autenticado(p_envelope_blob IN BLOB, p_chave IN VARCHAR2) RETURN BLOB;

  FUNCTION cripto_aes256_autenticado(p_texto_varchar2 IN VARCHAR2, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN VARCHAR2;
  FUNCTION descripto_aes256_autenticado(p_envelope_varchar2 IN VARCHAR2, p_chave IN VARCHAR2) RETURN VARCHAR2;
  FUNCTION cripto_aes256_autenticado(p_texto_clob IN CLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN CLOB;
  FUNCTION descripto_aes256_autenticado(p_envelope_clob IN CLOB, p_chave IN VARCHAR2) RETURN CLOB;
  FUNCTION cripto_aes256_autenticado(p_texto_blob IN BLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN BLOB;
  FUNCTION descripto_aes256_autenticado(p_envelope_blob IN BLOB, p_chave IN VARCHAR2) RETURN BLOB;

END criptopack;
/
