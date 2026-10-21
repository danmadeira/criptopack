-- Execute como script (por exemplo, F5 no SQL Developer).
-- Chaves e IV fixos abaixo são apenas didáticos; não os reutilize em produção.
-- Use named notation nos overloads AES: os nomes específicos do tipo evitam
-- ambiguidades de conversão implícita entre VARCHAR2, CLOB, BLOB, NUMBER e RAW.
DECLARE
  v_texto VARCHAR2(100) := 'Demonstração CRIPTOpack';
  v_texto_vazio VARCHAR2(1);
  v_numero NUMBER := 12345.678;
  v_clob CLOB;
  v_blob BLOB;
  v_raw RAW(32) := HEXTORAW('00010203040506070809A0B0C0D0E0F0');

  v_aes128_vc VARCHAR2(32767);
  v_aes128_clob CLOB;
  v_aes128_blob BLOB;
  v_aes128_raw RAW(32767);
  v_aes192_vc VARCHAR2(32767);
  v_aes192_clob CLOB;
  v_aes192_blob BLOB;
  v_aes192_raw RAW(32767);
  v_aes256_vc VARCHAR2(32767);
  v_aes256_clob CLOB;
  v_aes256_blob BLOB;
  v_aes256_raw RAW(32767);
  v_dec_clob CLOB;
  v_dec_blob BLOB;
  v_dec_raw RAW(32767);

  c_iv CONSTANT VARCHAR2(16) := '1234567890ABCDEF';
  c_chave128 CONSTANT VARCHAR2(16) := '0123456789ABCDEF';
  c_chave192 CONSTANT VARCHAR2(24) := '0123456789ABCDEFGHIJKLMN';
  c_chave256 CONSTANT VARCHAR2(32) := '0123456789ABCDEFGHIJKLMNOPQRSTUV';

  PROCEDURE mostrar(p_nome VARCHAR2, p_valor VARCHAR2) IS
  BEGIN
    DBMS_OUTPUT.PUT_LINE(
      RPAD(p_nome, 30) || ' = ' || p_valor
    );
  END mostrar;

  -- Exibe até 160 caracteres de um CLOB, para o resultado caber no console.
  PROCEDURE mostrar_clob(p_nome VARCHAR2, p_valor CLOB) IS
  BEGIN
    DBMS_OUTPUT.PUT_LINE(
      RPAD(p_nome, 30) || ' = ' || DBMS_LOB.SUBSTR(p_valor, 160, 1)
    );
  END mostrar_clob;

BEGIN
  -- Cria as fontes CLOB e BLOB a partir da mesma mensagem UTF-8.
  DBMS_LOB.CREATETEMPORARY(v_clob, TRUE);
  DBMS_LOB.WRITEAPPEND(v_clob, LENGTH(v_texto), v_texto);

  DBMS_LOB.CREATETEMPORARY(v_blob, TRUE);
  DBMS_LOB.WRITEAPPEND(
    v_blob,
    UTL_RAW.LENGTH(UTL_I18N.STRING_TO_RAW(v_texto, 'AL32UTF8')),
    UTL_I18N.STRING_TO_RAW(v_texto, 'AL32UTF8')
  );

  DBMS_OUTPUT.PUT_LINE('=== HASHES E CRC-32 ===');

  -- MD5: demonstra as sobrecargas para texto, CLOB, bytes de BLOB e NUMBER.
  mostrar('hash_md5(VARCHAR2)',
    criptopack.hash_md5(v_texto));
  mostrar('hash_md5(CLOB)',
    criptopack.hash_md5(v_clob));
  mostrar('hash_md5(BLOB)',
    criptopack.hash_md5(v_blob));
  mostrar('hash_md5(NUMBER)',
    criptopack.hash_md5(v_numero));

  -- SHA-1: calcula o digest para cada tipo de entrada suportado.
  mostrar('hash_sha1(VARCHAR2)',
    criptopack.hash_sha1(v_texto));
  mostrar('hash_sha1(CLOB)',
    criptopack.hash_sha1(v_clob));
  mostrar('hash_sha1(BLOB)',
    criptopack.hash_sha1(v_blob));
  mostrar('hash_sha1(NUMBER)',
    criptopack.hash_sha1(v_numero));

  -- SHA-256: calcula o digest para cada tipo de entrada suportado.
  mostrar('hash_sha256(VARCHAR2)',
    criptopack.hash_sha256(v_texto));
  mostrar('hash_sha256(CLOB)',
    criptopack.hash_sha256(v_clob));
  mostrar('hash_sha256(BLOB)',
    criptopack.hash_sha256(v_blob));
  mostrar('hash_sha256(NUMBER)',
    criptopack.hash_sha256(v_numero));

  -- SHA-384: calcula o digest para cada tipo de entrada suportado.
  mostrar('hash_sha384(VARCHAR2)',
    criptopack.hash_sha384(v_texto));
  mostrar('hash_sha384(CLOB)',
    criptopack.hash_sha384(v_clob));
  mostrar('hash_sha384(BLOB)',
    criptopack.hash_sha384(v_blob));
  mostrar('hash_sha384(NUMBER)',
    criptopack.hash_sha384(v_numero));

  -- SHA-512: calcula o digest para cada tipo de entrada suportado.
  mostrar('hash_sha512(VARCHAR2)',
    criptopack.hash_sha512(v_texto));
  mostrar('hash_sha512(CLOB)',
    criptopack.hash_sha512(v_clob));
  mostrar('hash_sha512(BLOB)',
    criptopack.hash_sha512(v_blob));
  mostrar('hash_sha512(NUMBER)',
    criptopack.hash_sha512(v_numero));

  -- SHA3-224: digest de 224 bits (56 caracteres hexadecimais).
  mostrar('hash_sha3_224(VARCHAR2)',
    criptopack.hash_sha3_224(v_texto));
  mostrar('hash_sha3_224(CLOB)',
    criptopack.hash_sha3_224(v_clob));
  mostrar('hash_sha3_224(BLOB)',
    criptopack.hash_sha3_224(v_blob));
  mostrar('hash_sha3_224(NUMBER)',
    criptopack.hash_sha3_224(v_numero));
  -- SHA3-224 esperado para v_texto em UTF-8:
  -- 33bd9a870e0d7eeff865a52d8aece2066b45745049b300e5fe2f19c1.
  -- Vetor SHA3-224 da entrada vazia:
  -- 6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7.
  mostrar('hash_sha3_224(vazio)',
    criptopack.hash_sha3_224(v_texto_vazio));

  -- SHA3-256: digest padronizado pelo NIST, distinto de SHA-256.
  mostrar('hash_sha3_256(VARCHAR2)',
    criptopack.hash_sha3_256(v_texto));
  mostrar('hash_sha3_256(CLOB)',
    criptopack.hash_sha3_256(v_clob));
  mostrar('hash_sha3_256(BLOB)',
    criptopack.hash_sha3_256(v_blob));
  mostrar('hash_sha3_256(NUMBER)',
    criptopack.hash_sha3_256(v_numero));
  -- SHA3-256 esperado para v_texto em UTF-8:
  -- 3797790699d40b6b9024ea28140e8011a67a7061358cef720a731c2b9ba9eac1.
  -- Vetor SHA3-256 da entrada vazia deve ser:
  -- a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a.
  mostrar('hash_sha3_256(vazio)',
    criptopack.hash_sha3_256(v_texto_vazio));

  -- SHA3-384: digest de 384 bits (96 caracteres hexadecimais).
  mostrar('hash_sha3_384(VARCHAR2)',
    criptopack.hash_sha3_384(v_texto));
  mostrar('hash_sha3_384(CLOB)',
    criptopack.hash_sha3_384(v_clob));
  mostrar('hash_sha3_384(BLOB)',
    criptopack.hash_sha3_384(v_blob));
  mostrar('hash_sha3_384(NUMBER)',
    criptopack.hash_sha3_384(v_numero));
  -- SHA3-384 esperado para v_texto em UTF-8:
  -- f03e7a532b9c6ea727e09b96d1ec978340d65e29e267d86f8fbb1b1d4c5b76a5
  -- 9d7a6da738338f802d2daac9f50eb9ae.

  -- SHA3-512: digest de 512 bits (128 caracteres hexadecimais).
  mostrar('hash_sha3_512(VARCHAR2)',
    criptopack.hash_sha3_512(v_texto));
  mostrar('hash_sha3_512(CLOB)',
    criptopack.hash_sha3_512(v_clob));
  mostrar('hash_sha3_512(BLOB)',
    criptopack.hash_sha3_512(v_blob));
  mostrar('hash_sha3_512(NUMBER)',
    criptopack.hash_sha3_512(v_numero));
  -- SHA3-512 esperado para v_texto em UTF-8:
  -- 81b12b396493a7429a911e01063671b411379896f98a640dbf59384db8d63d79
  -- b79dae32a5f0f1ce29bbc777fda4581a3de87150839b064528ef92ad3cd5d221.
  -- Vetor SHA3-512 da entrada vazia deve ser:
  -- a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6
  -- 15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26.
  mostrar('hash_sha3_512(vazio)',
    criptopack.hash_sha3_512(v_texto_vazio));

  -- CRC-32/ISO-HDLC: checksum demonstrativo para texto, LOBs e NUMBER.
  mostrar('hash_crc32(VARCHAR2)',
    criptopack.hash_crc32(v_texto));
  mostrar('hash_crc32(CLOB)',
    criptopack.hash_crc32(v_clob));
  mostrar('hash_crc32(BLOB)',
    criptopack.hash_crc32(v_blob));
  mostrar('hash_crc32(NUMBER)',
    criptopack.hash_crc32(v_numero));

  -- AES-128 usa chave de 16 bytes, CBC e padding PKCS#7.
  DBMS_OUTPUT.PUT_LINE(CHR(10) || '=== AES-128-CBC/PKCS#7 ===');
  -- VARCHAR2: cifra para hexadecimal e decifra de volta para texto.
  v_aes128_vc := criptopack.cripto_aes128(
    p_texto_varchar2 => v_texto,
    p_chave => c_chave128,
    p_iv => c_iv
  );
  mostrar('cripto_aes128(VARCHAR2)', v_aes128_vc);
  mostrar('descripto_aes128(VARCHAR2)',
    criptopack.descripto_aes128(
      p_cifra_varchar2 => v_aes128_vc,
      p_chave => c_chave128,
      p_iv => c_iv
    )
  );

  -- CLOB: o ciphertext hexadecimal é devolvido como CLOB.
  v_aes128_clob := criptopack.cripto_aes128(
    p_texto_clob => v_clob,
    p_chave => c_chave128,
    p_iv => c_iv
  );
  mostrar_clob('cripto_aes128(CLOB)', v_aes128_clob);
  v_dec_clob := criptopack.descripto_aes128(
    p_cifra_clob => v_aes128_clob,
    p_chave => c_chave128,
    p_iv => c_iv
  );
  mostrar_clob('descripto_aes128(CLOB)', v_dec_clob);
  DBMS_LOB.FREETEMPORARY(v_dec_clob);

  -- BLOB: cifragem e decifragem preservam o conteúdo binário.
  v_aes128_blob := criptopack.cripto_aes128(
    p_texto_blob => v_blob,
    p_chave => c_chave128,
    p_iv => c_iv
  );
  mostrar('cripto_aes128(BLOB) bytes', TO_CHAR(DBMS_LOB.GETLENGTH(v_aes128_blob)));
  v_dec_blob := criptopack.descripto_aes128(
    p_cifra_blob => v_aes128_blob,
    p_chave => c_chave128,
    p_iv => c_iv
  );
  mostrar('descripto_aes128(BLOB)', CASE WHEN DBMS_LOB.COMPARE(v_dec_blob, v_blob) = 0
    THEN 'round-trip OK'
    ELSE 'DIVERGÊNCIA'
  END);
  DBMS_LOB.FREETEMPORARY(v_dec_blob);

  -- NUMBER: cifra a representação decimal TM9; o decrypt valida e devolve texto.
  v_aes128_vc := criptopack.cripto_aes128(
    p_numero => v_numero,
    p_chave => c_chave128,
    p_iv => c_iv
  );
  mostrar('cripto_aes128(NUMBER)', v_aes128_vc);
  mostrar('descripto_aes128(NUMBER)',
    criptopack.descripto_aes128(
      p_cifra_varchar2 => v_aes128_vc,
      p_chave => c_chave128,
      p_iv => c_iv,
      p_tipo => 'NUMBER'
    )
  );

  -- RAW: demonstra dados binários sem conversão de charset.
  v_aes128_raw := criptopack.cripto_aes128(
    p_texto_raw => v_raw,
    p_chave => c_chave128,
    p_iv => c_iv
  );
  mostrar('cripto_aes128(RAW)', RAWTOHEX(v_aes128_raw));
  v_dec_raw := criptopack.descripto_aes128(
    p_cifra_raw => v_aes128_raw,
    p_chave => c_chave128,
    p_iv => c_iv
  );
  mostrar('descripto_aes128(RAW)', CASE WHEN UTL_RAW.COMPARE(v_dec_raw, v_raw) = 0
    THEN 'round-trip OK'
    ELSE 'DIVERGÊNCIA'
  END);

  -- AES-192 usa chave de 24 bytes, CBC e padding PKCS#7.
  DBMS_OUTPUT.PUT_LINE(CHR(10) || '=== AES-192-CBC/PKCS#7 ===');
  -- VARCHAR2: cifra para hexadecimal e decifra de volta para texto.
  v_aes192_vc := criptopack.cripto_aes192(
    p_texto_varchar2 => v_texto,
    p_chave => c_chave192,
    p_iv => c_iv
  );
  mostrar('cripto_aes192(VARCHAR2)', v_aes192_vc);
  mostrar('descripto_aes192(VARCHAR2)',
    criptopack.descripto_aes192(
      p_cifra_varchar2 => v_aes192_vc,
      p_chave => c_chave192,
      p_iv => c_iv
    )
  );

  -- CLOB: o ciphertext hexadecimal é devolvido como CLOB.
  v_aes192_clob := criptopack.cripto_aes192(
    p_texto_clob => v_clob,
    p_chave => c_chave192,
    p_iv => c_iv
  );
  mostrar_clob('cripto_aes192(CLOB)', v_aes192_clob);
  v_dec_clob := criptopack.descripto_aes192(
    p_cifra_clob => v_aes192_clob,
    p_chave => c_chave192,
    p_iv => c_iv
  );
  mostrar_clob('descripto_aes192(CLOB)', v_dec_clob);
  DBMS_LOB.FREETEMPORARY(v_dec_clob);

  -- BLOB: cifragem e decifragem preservam o conteúdo binário.
  v_aes192_blob := criptopack.cripto_aes192(
    p_texto_blob => v_blob,
    p_chave => c_chave192,
    p_iv => c_iv
  );
  mostrar('cripto_aes192(BLOB) bytes', TO_CHAR(DBMS_LOB.GETLENGTH(v_aes192_blob)));
  v_dec_blob := criptopack.descripto_aes192(
    p_cifra_blob => v_aes192_blob,
    p_chave => c_chave192,
    p_iv => c_iv
  );
  mostrar('descripto_aes192(BLOB)', CASE WHEN DBMS_LOB.COMPARE(v_dec_blob, v_blob) = 0
    THEN 'round-trip OK'
    ELSE 'DIVERGÊNCIA'
  END);
  DBMS_LOB.FREETEMPORARY(v_dec_blob);

  -- NUMBER: cifra a representação decimal TM9; o decrypt valida e devolve texto.
  v_aes192_vc := criptopack.cripto_aes192(
    p_numero => v_numero,
    p_chave => c_chave192,
    p_iv => c_iv
  );
  mostrar('cripto_aes192(NUMBER)', v_aes192_vc);
  mostrar('descripto_aes192(NUMBER)',
    criptopack.descripto_aes192(
      p_cifra_varchar2 => v_aes192_vc,
      p_chave => c_chave192,
      p_iv => c_iv,
      p_tipo => 'NUMBER'
    )
  );

  -- RAW: demonstra dados binários sem conversão de charset.
  v_aes192_raw := criptopack.cripto_aes192(
    p_texto_raw => v_raw,
    p_chave => c_chave192,
    p_iv => c_iv
  );
  mostrar('cripto_aes192(RAW)', RAWTOHEX(v_aes192_raw));
  v_dec_raw := criptopack.descripto_aes192(
    p_cifra_raw => v_aes192_raw,
    p_chave => c_chave192,
    p_iv => c_iv
  );
  mostrar('descripto_aes192(RAW)', CASE WHEN UTL_RAW.COMPARE(v_dec_raw, v_raw) = 0
    THEN 'round-trip OK'
    ELSE 'DIVERGÊNCIA'
  END);

  -- AES-256 usa chave de 32 bytes, CBC e padding PKCS#7.
  DBMS_OUTPUT.PUT_LINE(CHR(10) || '=== AES-256-CBC/PKCS#7 ===');
  -- VARCHAR2: cifra para hexadecimal e decifra de volta para texto.
  v_aes256_vc := criptopack.cripto_aes256(
    p_texto_varchar2 => v_texto,
    p_chave => c_chave256,
    p_iv => c_iv
  );
  mostrar('cripto_aes256(VARCHAR2)', v_aes256_vc);
  mostrar('descripto_aes256(VARCHAR2)',
    criptopack.descripto_aes256(
      p_cifra_varchar2 => v_aes256_vc,
      p_chave => c_chave256,
      p_iv => c_iv
    )
  );

  -- CLOB: o ciphertext hexadecimal é devolvido como CLOB.
  v_aes256_clob := criptopack.cripto_aes256(
    p_texto_clob => v_clob,
    p_chave => c_chave256,
    p_iv => c_iv
  );
  mostrar_clob('cripto_aes256(CLOB)', v_aes256_clob);
  v_dec_clob := criptopack.descripto_aes256(
    p_cifra_clob => v_aes256_clob,
    p_chave => c_chave256,
    p_iv => c_iv
  );
  mostrar_clob('descripto_aes256(CLOB)', v_dec_clob);
  DBMS_LOB.FREETEMPORARY(v_dec_clob);

  -- BLOB: cifragem e decifragem preservam o conteúdo binário.
  v_aes256_blob := criptopack.cripto_aes256(
    p_texto_blob => v_blob,
    p_chave => c_chave256,
    p_iv => c_iv
  );
  mostrar('cripto_aes256(BLOB) bytes', TO_CHAR(DBMS_LOB.GETLENGTH(v_aes256_blob)));
  v_dec_blob := criptopack.descripto_aes256(
    p_cifra_blob => v_aes256_blob,
    p_chave => c_chave256,
    p_iv => c_iv
  );
  mostrar('descripto_aes256(BLOB)', CASE WHEN DBMS_LOB.COMPARE(v_dec_blob, v_blob) = 0
    THEN 'round-trip OK'
    ELSE 'DIVERGÊNCIA'
  END);
  DBMS_LOB.FREETEMPORARY(v_dec_blob);

  -- NUMBER: cifra a representação decimal TM9; o decrypt valida e devolve texto.
  v_aes256_vc := criptopack.cripto_aes256(
    p_numero => v_numero,
    p_chave => c_chave256,
    p_iv => c_iv
  );
  mostrar('cripto_aes256(NUMBER)', v_aes256_vc);
  mostrar('descripto_aes256(NUMBER)',
    criptopack.descripto_aes256(
      p_cifra_varchar2 => v_aes256_vc,
      p_chave => c_chave256,
      p_iv => c_iv,
      p_tipo => 'NUMBER'
    )
  );

  -- RAW: demonstra dados binários sem conversão de charset.
  v_aes256_raw := criptopack.cripto_aes256(
    p_texto_raw => v_raw,
    p_chave => c_chave256,
    p_iv => c_iv
  );
  mostrar('cripto_aes256(RAW)', RAWTOHEX(v_aes256_raw));
  v_dec_raw := criptopack.descripto_aes256(
    p_cifra_raw => v_aes256_raw,
    p_chave => c_chave256,
    p_iv => c_iv
  );
  mostrar('descripto_aes256(RAW)', CASE WHEN UTL_RAW.COMPARE(v_dec_raw, v_raw) = 0
    THEN 'round-trip OK'
    ELSE 'DIVERGÊNCIA'
  END);

  -- Libera os LOBs temporários alocados durante a demonstração.
  DBMS_LOB.FREETEMPORARY(v_clob);
  DBMS_LOB.FREETEMPORARY(v_blob);
  DBMS_LOB.FREETEMPORARY(v_aes128_clob);
  DBMS_LOB.FREETEMPORARY(v_aes128_blob);
  DBMS_LOB.FREETEMPORARY(v_aes192_clob);
  DBMS_LOB.FREETEMPORARY(v_aes192_blob);
  DBMS_LOB.FREETEMPORARY(v_aes256_clob);
  DBMS_LOB.FREETEMPORARY(v_aes256_blob);
EXCEPTION
  WHEN OTHERS THEN
    IF DBMS_LOB.ISTEMPORARY(v_dec_clob) = 1 THEN DBMS_LOB.FREETEMPORARY(v_dec_clob); END IF;
    IF DBMS_LOB.ISTEMPORARY(v_clob) = 1 THEN DBMS_LOB.FREETEMPORARY(v_clob); END IF;
    IF DBMS_LOB.ISTEMPORARY(v_blob) = 1 THEN DBMS_LOB.FREETEMPORARY(v_blob); END IF;
    IF DBMS_LOB.ISTEMPORARY(v_aes128_clob) = 1 THEN DBMS_LOB.FREETEMPORARY(v_aes128_clob); END IF;
    IF DBMS_LOB.ISTEMPORARY(v_aes128_blob) = 1 THEN DBMS_LOB.FREETEMPORARY(v_aes128_blob); END IF;
    IF DBMS_LOB.ISTEMPORARY(v_aes192_clob) = 1 THEN DBMS_LOB.FREETEMPORARY(v_aes192_clob); END IF;
    IF DBMS_LOB.ISTEMPORARY(v_aes192_blob) = 1 THEN DBMS_LOB.FREETEMPORARY(v_aes192_blob); END IF;
    IF DBMS_LOB.ISTEMPORARY(v_aes256_clob) = 1 THEN DBMS_LOB.FREETEMPORARY(v_aes256_clob); END IF;
    IF DBMS_LOB.ISTEMPORARY(v_aes256_blob) = 1 THEN DBMS_LOB.FREETEMPORARY(v_aes256_blob); END IF;
    IF DBMS_LOB.ISTEMPORARY(v_dec_blob) = 1 THEN DBMS_LOB.FREETEMPORARY(v_dec_blob); END IF;
    RAISE;
END;
/
