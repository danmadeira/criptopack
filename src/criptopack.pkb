CREATE OR REPLACE PACKAGE BODY criptopack AS
  /**
   * @author Daniel Madeira
   * @version 1.0
   * @date 2026-10-21
   * @brief Descreve a implementação de hashes, CRC e criptografia AES.
   *
   * O corpo implementa MD5, SHA-1, SHA-256, SHA3-224, SHA3-256, SHA3-384,
   * SHA3-512, SHA-384, SHA-512,
   * CRC-32/ISO-HDLC e AES-128/192/256-CBC com padding PKCS#7, incluindo
   * rotinas internas de processamento de bytes e LOBs. Não depende de
   * DBMS_CRYPTO. Textos usam UTF-8; hashes e ciphertexts textuais usam
   * hexadecimal; BLOB e RAW preservam bytes binários.
   *
   * CBC não autentica o ciphertext: o chamador deve usar IV imprevisível
   * e único por operação e proteger a integridade separadamente. MD5 e
   * SHA não são KDFs e não devem ser usados para derivar chave de senha.
   *
   * @return Implementações executáveis e rotinas privadas da package.
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

  c_mod32 CONSTANT NUMBER := 4294967296;

  FUNCTION bit_and32(p_a NUMBER, p_b NUMBER) RETURN NUMBER IS
    l_a NUMBER := p_a;
    l_b NUMBER := p_b;
    l_result NUMBER := 0;
    l_place NUMBER := 1;
  BEGIN
    FOR i IN 1 .. 32 LOOP
      IF MOD(l_a, 2) = 1 AND MOD(l_b, 2) = 1 THEN
        l_result := l_result + l_place;
      END IF;
      l_a := TRUNC(l_a / 2);
      l_b := TRUNC(l_b / 2);
      l_place := l_place * 2;
    END LOOP;
    RETURN l_result;
  END bit_and32;

  FUNCTION bit_xor32(p_a NUMBER, p_b NUMBER) RETURN NUMBER IS
    l_a NUMBER := p_a;
    l_b NUMBER := p_b;
    l_result NUMBER := 0;
    l_place NUMBER := 1;
  BEGIN
    FOR i IN 1 .. 32 LOOP
      IF MOD(l_a, 2) <> MOD(l_b, 2) THEN
        l_result := l_result + l_place;
      END IF;
      l_a := TRUNC(l_a / 2);
      l_b := TRUNC(l_b / 2);
      l_place := l_place * 2;
    END LOOP;
    RETURN l_result;
  END bit_xor32;

  FUNCTION bit_or32(p_a NUMBER, p_b NUMBER) RETURN NUMBER IS
  BEGIN
    RETURN p_a + p_b - bit_and32(p_a, p_b);
  END bit_or32;

  FUNCTION rotate_left32(p_value NUMBER, p_bits PLS_INTEGER) RETURN NUMBER IS
    l_power NUMBER := POWER(2, p_bits);
  BEGIN
    RETURN MOD(
      TRUNC(p_value / POWER(2, 32 - p_bits)) +
      MOD(p_value, POWER(2, 32 - p_bits)) * l_power,
      c_mod32
    );
  END rotate_left32;

  FUNCTION aes_gf_mul(p_a PLS_INTEGER, p_b PLS_INTEGER) RETURN PLS_INTEGER IS
    l_a PLS_INTEGER := p_a;
    l_b PLS_INTEGER := p_b;
    l_result PLS_INTEGER := 0;
  BEGIN
    FOR i IN 1 .. 8 LOOP
      IF MOD(l_b, 2) = 1 THEN
        l_result := bit_xor32(l_result, l_a);
      END IF;
      l_b := TRUNC(l_b / 2);
      l_a := l_a * 2;
      IF l_a >= 256 THEN
        l_a := bit_xor32(l_a, 283); -- irreducible polynomial 0x11B
      END IF;
    END LOOP;
    RETURN l_result;
  END aes_gf_mul;

  FUNCTION aes_gf_inverse(p_value PLS_INTEGER) RETURN PLS_INTEGER IS
    l_base PLS_INTEGER := p_value;
    l_exponent PLS_INTEGER := 254;
    l_result PLS_INTEGER := 1;
  BEGIN
    IF p_value = 0 THEN
      RETURN 0;
    END IF;
    WHILE l_exponent > 0 LOOP
      IF MOD(l_exponent, 2) = 1 THEN
        l_result := aes_gf_mul(l_result, l_base);
      END IF;
      l_base := aes_gf_mul(l_base, l_base);
      l_exponent := TRUNC(l_exponent / 2);
    END LOOP;
    RETURN l_result;
  END aes_gf_inverse;

  FUNCTION aes_rotl8(p_value PLS_INTEGER, p_bits PLS_INTEGER) RETURN PLS_INTEGER IS
  BEGIN
    RETURN MOD(p_value * POWER(2, p_bits) + TRUNC(p_value / POWER(2, 8 - p_bits)), 256);
  END aes_rotl8;

  FUNCTION aes_sbox(p_value PLS_INTEGER) RETURN PLS_INTEGER IS
    l_inverse PLS_INTEGER := aes_gf_inverse(p_value);
  BEGIN
    RETURN bit_xor32(
      bit_xor32(l_inverse,
        bit_xor32(bit_xor32(aes_rotl8(l_inverse, 1), aes_rotl8(l_inverse, 2)),
                  bit_xor32(aes_rotl8(l_inverse, 3), aes_rotl8(l_inverse, 4)))),
      99
    );
  END aes_sbox;

  FUNCTION aes_inv_sbox(p_value PLS_INTEGER) RETURN PLS_INTEGER IS
    l_affine PLS_INTEGER;
  BEGIN
    l_affine := bit_xor32(
      bit_xor32(bit_xor32(aes_rotl8(p_value, 1), aes_rotl8(p_value, 3)),
                aes_rotl8(p_value, 6)),
      5
    );
    RETURN aes_gf_inverse(l_affine);
  END aes_inv_sbox;

  FUNCTION aes_byte(p_raw RAW, p_position PLS_INTEGER) RETURN PLS_INTEGER IS
    c_hex CONSTANT VARCHAR2(16) := '0123456789ABCDEF';
    l_hex VARCHAR2(2) := RAWTOHEX(UTL_RAW.SUBSTR(p_raw, p_position, 1));
  BEGIN
    RETURN (INSTR(c_hex, SUBSTR(l_hex, 1, 1)) - 1) * 16
         + INSTR(c_hex, SUBSTR(l_hex, 2, 1)) - 1;
  END aes_byte;

  FUNCTION aes_byte_hex(p_value PLS_INTEGER) RETURN VARCHAR2 IS
    c_hex CONSTANT VARCHAR2(16) := '0123456789ABCDEF';
  BEGIN
    RETURN SUBSTR(c_hex, TRUNC(p_value / 16) + 1, 1)
         || SUBSTR(c_hex, MOD(p_value, 16) + 1, 1);
  END aes_byte_hex;

  FUNCTION aes_block(p_block RAW, p_key RAW, p_decrypt BOOLEAN) RETURN RAW IS
    TYPE t_byte_array IS TABLE OF PLS_INTEGER INDEX BY PLS_INTEGER;
    l_state t_byte_array;
    l_round_keys t_byte_array;
    l_temp t_byte_array;
    l_rcon PLS_INTEGER := 1;
    l_word PLS_INTEGER;
    l_hex VARCHAR2(32);
    l_source_index PLS_INTEGER;
    l_key_words PLS_INTEGER;
    l_rounds PLS_INTEGER;
    l_total_words PLS_INTEGER;
    l_a PLS_INTEGER;
    l_b PLS_INTEGER;
    l_c PLS_INTEGER;
    l_d PLS_INTEGER;

    PROCEDURE add_round_key(p_round PLS_INTEGER) IS
    BEGIN
      FOR i IN 0 .. 15 LOOP
        l_state(i) := bit_xor32(l_state(i), l_round_keys(p_round * 16 + i));
      END LOOP;
    END add_round_key;

    PROCEDURE substitute_bytes(p_inverse BOOLEAN) IS
    BEGIN
      FOR i IN 0 .. 15 LOOP
        IF p_inverse THEN
          l_state(i) := aes_inv_sbox(l_state(i));
        ELSE
          l_state(i) := aes_sbox(l_state(i));
        END IF;
      END LOOP;
    END substitute_bytes;

    PROCEDURE shift_rows(p_inverse BOOLEAN) IS
    BEGIN
      FOR r IN 1 .. 3 LOOP
        FOR col IN 0 .. 3 LOOP
          IF p_inverse THEN
            l_source_index := MOD(col - r + 4, 4) * 4 + r;
          ELSE
            l_source_index := MOD(col + r, 4) * 4 + r;
          END IF;
          l_temp(col * 4 + r) := l_state(l_source_index);
        END LOOP;
      END LOOP;
      FOR r IN 1 .. 3 LOOP
        FOR col IN 0 .. 3 LOOP
          l_state(col * 4 + r) := l_temp(col * 4 + r);
        END LOOP;
      END LOOP;
    END shift_rows;

    PROCEDURE mix_columns(p_inverse BOOLEAN) IS
    BEGIN
      FOR col IN 0 .. 3 LOOP
        l_a := l_state(col * 4);
        l_b := l_state(col * 4 + 1);
        l_c := l_state(col * 4 + 2);
        l_d := l_state(col * 4 + 3);
        IF p_inverse THEN
          l_state(col * 4) := bit_xor32(bit_xor32(aes_gf_mul(l_a, 14), aes_gf_mul(l_b, 11)),
                                         bit_xor32(aes_gf_mul(l_c, 13), aes_gf_mul(l_d, 9)));
          l_state(col * 4 + 1) := bit_xor32(bit_xor32(aes_gf_mul(l_a, 9), aes_gf_mul(l_b, 14)),
                                             bit_xor32(aes_gf_mul(l_c, 11), aes_gf_mul(l_d, 13)));
          l_state(col * 4 + 2) := bit_xor32(bit_xor32(aes_gf_mul(l_a, 13), aes_gf_mul(l_b, 9)),
                                             bit_xor32(aes_gf_mul(l_c, 14), aes_gf_mul(l_d, 11)));
          l_state(col * 4 + 3) := bit_xor32(bit_xor32(aes_gf_mul(l_a, 11), aes_gf_mul(l_b, 13)),
                                             bit_xor32(aes_gf_mul(l_c, 9), aes_gf_mul(l_d, 14)));
        ELSE
          l_state(col * 4) := bit_xor32(bit_xor32(aes_gf_mul(l_a, 2), aes_gf_mul(l_b, 3)),
                                         bit_xor32(l_c, l_d));
          l_state(col * 4 + 1) := bit_xor32(bit_xor32(l_a, aes_gf_mul(l_b, 2)),
                                             bit_xor32(aes_gf_mul(l_c, 3), l_d));
          l_state(col * 4 + 2) := bit_xor32(bit_xor32(l_a, l_b),
                                             bit_xor32(aes_gf_mul(l_c, 2), aes_gf_mul(l_d, 3)));
          l_state(col * 4 + 3) := bit_xor32(bit_xor32(aes_gf_mul(l_a, 3), l_b),
                                             bit_xor32(l_c, aes_gf_mul(l_d, 2)));
        END IF;
      END LOOP;
    END mix_columns;
  BEGIN
    IF NVL(UTL_RAW.LENGTH(p_block), 0) != 16 OR
      NVL(UTL_RAW.LENGTH(p_key), 0) NOT IN (16, 24, 32) THEN
          RAISE_APPLICATION_ERROR(-20001, 'AES exige blocos de 16 bytes e chave de 16, 24 ou 32 bytes.');
    END IF;
    l_key_words := UTL_RAW.LENGTH(p_key) / 4;
    l_rounds := l_key_words + 6;
    l_total_words := 4 * (l_rounds + 1);
    FOR i IN 0 .. 15 LOOP
      l_state(i) := aes_byte(p_block, i + 1);
    END LOOP;
    FOR i IN 0 .. UTL_RAW.LENGTH(p_key) - 1 LOOP
      l_round_keys(i) := aes_byte(p_key, i + 1);
    END LOOP;

    FOR word_index IN l_key_words .. l_total_words - 1 LOOP
      l_word := (word_index - 1) * 4;
      l_temp(0) := l_round_keys(l_word);
      l_temp(1) := l_round_keys(l_word + 1);
      l_temp(2) := l_round_keys(l_word + 2);
      l_temp(3) := l_round_keys(l_word + 3);
      IF MOD(word_index, l_key_words) = 0 THEN
        l_temp(0) := aes_sbox(l_temp(1));
        l_temp(1) := aes_sbox(l_temp(2));
        l_temp(2) := aes_sbox(l_temp(3));
        l_temp(3) := aes_sbox(l_round_keys(l_word));
        l_temp(0) := bit_xor32(l_temp(0), l_rcon);
        l_rcon := aes_gf_mul(l_rcon, 2);
      ELSIF l_key_words = 8 AND MOD(word_index, l_key_words) = 4 THEN
        FOR j IN 0 .. 3 LOOP
          l_temp(j) := aes_sbox(l_temp(j));
        END LOOP;
      END IF;
      FOR j IN 0 .. 3 LOOP
        l_round_keys(word_index * 4 + j) := bit_xor32(
          l_round_keys((word_index - l_key_words) * 4 + j), l_temp(j)
        );
      END LOOP;
    END LOOP;

    IF NOT p_decrypt THEN
      add_round_key(0);
      FOR round_index IN 1 .. l_rounds - 1 LOOP
        substitute_bytes(FALSE);
        shift_rows(FALSE);
        mix_columns(FALSE);
        add_round_key(round_index);
      END LOOP;
      substitute_bytes(FALSE);
      shift_rows(FALSE);
      add_round_key(l_rounds);
    ELSE
      add_round_key(l_rounds);
      FOR round_index IN REVERSE 1 .. l_rounds - 1 LOOP
        shift_rows(TRUE);
        substitute_bytes(TRUE);
        add_round_key(round_index);
        mix_columns(TRUE);
      END LOOP;
      shift_rows(TRUE);
      substitute_bytes(TRUE);
      add_round_key(0);
    END IF;

    FOR i IN 0 .. 15 LOOP
      l_hex := l_hex || aes_byte_hex(l_state(i));
    END LOOP;
    RETURN HEXTORAW(l_hex);
  END aes_block;

  FUNCTION aes_xor_raw(p_left RAW, p_right RAW) RETURN RAW IS
    l_hex VARCHAR2(32);
  BEGIN
    IF UTL_RAW.LENGTH(p_left) != UTL_RAW.LENGTH(p_right) THEN
      RAISE_APPLICATION_ERROR(-20002, 'Os blocos AES devem ter o mesmo tamanho.');
    END IF;
    FOR i IN 1 .. UTL_RAW.LENGTH(p_left) LOOP
      l_hex := l_hex || aes_byte_hex(bit_xor32(aes_byte(p_left, i), aes_byte(p_right, i)));
    END LOOP;
    RETURN HEXTORAW(l_hex);
  END aes_xor_raw;

  PROCEDURE validate_aes_key_iv(p_key RAW, p_iv RAW, p_key_length PLS_INTEGER DEFAULT 16) IS
  BEGIN
    IF NVL(UTL_RAW.LENGTH(p_key), 0) != p_key_length THEN
      RAISE_APPLICATION_ERROR(-20003, 'A chave AES deve ter exatamente ' || p_key_length || ' bytes UTF-8.');
    END IF;
    IF NVL(UTL_RAW.LENGTH(p_iv), 0) != 16 THEN
      RAISE_APPLICATION_ERROR(-20004, 'O IV do modo CBC deve ter exatamente 16 bytes UTF-8.');
    END IF;
  END validate_aes_key_iv;

  FUNCTION aes_encrypt_blob(p_data BLOB, p_key RAW, p_iv RAW, p_key_length PLS_INTEGER DEFAULT 16) RETURN BLOB IS
    l_result BLOB;
    l_length NUMBER := 0;
    l_offset NUMBER := 1;
    l_block RAW(16);
    l_tail RAW(16);
    l_pad PLS_INTEGER;
    l_tail_length PLS_INTEGER;
    l_previous RAW(16) := p_iv;
    l_encrypted RAW(16);
    l_hex VARCHAR2(32);
  BEGIN
    validate_aes_key_iv(p_key, p_iv, p_key_length);
    DBMS_LOB.CREATETEMPORARY(l_result, TRUE);
    IF p_data IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_data);
    END IF;
    WHILE l_offset + 15 <= l_length LOOP
      l_block := DBMS_LOB.SUBSTR(p_data, 16, l_offset);
      l_encrypted := aes_block(aes_xor_raw(l_block, l_previous), p_key, FALSE);
      DBMS_LOB.WRITEAPPEND(l_result, 16, l_encrypted);
      l_previous := l_encrypted;
      l_offset := l_offset + 16;
    END LOOP;

    l_tail_length := MOD(l_length, 16);
    l_pad := 16 - l_tail_length;
    IF l_tail_length > 0 THEN
      l_tail := DBMS_LOB.SUBSTR(p_data, l_tail_length, l_offset);
      l_hex := RAWTOHEX(l_tail);
    END IF;
    FOR i IN 1 .. l_pad LOOP
      l_hex := l_hex || aes_byte_hex(l_pad);
    END LOOP;
    l_tail := HEXTORAW(l_hex);
    l_encrypted := aes_block(aes_xor_raw(l_tail, l_previous), p_key, FALSE);
    DBMS_LOB.WRITEAPPEND(l_result, 16, l_encrypted);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_result) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_result);
      END IF;
      RAISE;
  END aes_encrypt_blob;

  FUNCTION aes_decrypt_blob(p_data BLOB, p_key RAW, p_iv RAW, p_key_length PLS_INTEGER DEFAULT 16) RETURN BLOB IS
    l_result BLOB;
    l_length NUMBER := 0;
    l_offset NUMBER := 1;
    l_block RAW(16);
    l_plain RAW(16);
    l_previous RAW(16) := p_iv;
    l_current RAW(16);
    l_last_byte PLS_INTEGER;
    l_write_length PLS_INTEGER;
  BEGIN
    validate_aes_key_iv(p_key, p_iv, p_key_length);
    IF p_data IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_data);
    END IF;
    IF l_length = 0 OR MOD(l_length, 16) != 0 THEN
      RAISE_APPLICATION_ERROR(-20005, 'O ciphertext AES-CBC deve conter blocos completos.');
    END IF;
    DBMS_LOB.CREATETEMPORARY(l_result, TRUE);
    WHILE l_offset <= l_length LOOP
      l_current := DBMS_LOB.SUBSTR(p_data, 16, l_offset);
      l_plain := aes_xor_raw(aes_block(l_current, p_key, TRUE), l_previous);
      IF l_offset + 15 = l_length THEN
        l_last_byte := aes_byte(l_plain, 16);
        IF l_last_byte < 1 OR l_last_byte > 16 THEN
          RAISE_APPLICATION_ERROR(-20006, 'Padding AES inválido: chave ou IV incorretos.');
        END IF;
        FOR i IN 16 - l_last_byte + 1 .. 16 LOOP
          IF aes_byte(l_plain, i) != l_last_byte THEN
            RAISE_APPLICATION_ERROR(-20006, 'Padding AES inválido: chave ou IV incorretos.');
          END IF;
        END LOOP;
        l_write_length := 16 - l_last_byte;
        IF l_write_length > 0 THEN
          DBMS_LOB.WRITEAPPEND(l_result, l_write_length, UTL_RAW.SUBSTR(l_plain, 1, l_write_length));
        END IF;
      ELSE
        DBMS_LOB.WRITEAPPEND(l_result, 16, l_plain);
      END IF;
      l_previous := l_current;
      l_offset := l_offset + 16;
    END LOOP;
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_result) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_result);
      END IF;
      RAISE;
  END aes_decrypt_blob;

  FUNCTION aes_hex_blob(p_data BLOB) RETURN CLOB IS
    l_result CLOB;
    l_offset NUMBER := 1;
    l_length NUMBER := 0;
    l_raw RAW(4000);
    l_hex VARCHAR2(8000);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_result, TRUE);
    IF p_data IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_data);
    END IF;
    WHILE l_offset <= l_length LOOP
      l_raw := DBMS_LOB.SUBSTR(p_data, 4000, l_offset);
      l_hex := RAWTOHEX(l_raw);
      DBMS_LOB.WRITEAPPEND(l_result, LENGTH(l_hex), l_hex);
      l_offset := l_offset + UTL_RAW.LENGTH(l_raw);
    END LOOP;
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_result) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_result);
      END IF;
      RAISE;
  END aes_hex_blob;

  FUNCTION aes_unhex_clob(p_hex CLOB) RETURN BLOB IS
    l_result BLOB;
    l_length NUMBER := 0;
    l_offset NUMBER := 1;
    l_chunk VARCHAR2(8000);
    l_raw RAW(4000);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_result, TRUE);
    IF p_hex IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_hex);
    END IF;
    IF MOD(l_length, 2) != 0 THEN
      RAISE_APPLICATION_ERROR(-20007, 'Ciphertext hexadecimal deve ter quantidade par de caracteres.');
    END IF;
    WHILE l_offset <= l_length LOOP
      l_chunk := DBMS_LOB.SUBSTR(p_hex, 8000, l_offset);
      IF MOD(LENGTH(l_chunk), 2) != 0 THEN
        l_chunk := l_chunk || DBMS_LOB.SUBSTR(p_hex, 1, l_offset + LENGTH(l_chunk));
      END IF;
      l_raw := HEXTORAW(l_chunk);
      DBMS_LOB.WRITEAPPEND(l_result, UTL_RAW.LENGTH(l_raw), l_raw);
      l_offset := l_offset + LENGTH(l_chunk);
    END LOOP;
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_result) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_result);
      END IF;
      RAISE;
  END aes_unhex_clob;

  FUNCTION aes_clob_to_blob(p_text CLOB) RETURN BLOB IS
    l_blob BLOB;
    l_dest_offset INTEGER := 1;
    l_src_offset INTEGER := 1;
    l_lang_context INTEGER := DBMS_LOB.DEFAULT_LANG_CTX;
    l_warning INTEGER;
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    IF p_text IS NOT NULL THEN
      DBMS_LOB.CONVERTTOBLOB(
        l_blob, p_text, DBMS_LOB.LOBMAXSIZE, l_dest_offset, l_src_offset,
        NLS_CHARSET_ID('AL32UTF8'), l_lang_context, l_warning
      );
      IF l_warning != 0 THEN
        RAISE_APPLICATION_ERROR(-20008, 'Falha ao converter CLOB para UTF-8.');
      END IF;
    END IF;
    RETURN l_blob;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_blob);
      END IF;
      RAISE;
  END aes_clob_to_blob;

  FUNCTION aes_blob_to_clob(p_data BLOB) RETURN CLOB IS
    l_clob CLOB;
    l_dest_offset INTEGER := 1;
    l_src_offset INTEGER := 1;
    l_lang_context INTEGER := DBMS_LOB.DEFAULT_LANG_CTX;
    l_warning INTEGER;
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_clob, TRUE);
    IF p_data IS NOT NULL THEN
      DBMS_LOB.CONVERTTOCLOB(
        l_clob, p_data, DBMS_LOB.LOBMAXSIZE, l_dest_offset, l_src_offset,
        NLS_CHARSET_ID('AL32UTF8'), l_lang_context, l_warning
      );
      IF l_warning != 0 THEN
        RAISE_APPLICATION_ERROR(-20009, 'Os bytes descriptografados não são UTF-8 válido.');
      END IF;
    END IF;
    RETURN l_clob;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_clob) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_clob);
      END IF;
      RAISE;
  END aes_blob_to_clob;

  FUNCTION aes_key_raw(p_value VARCHAR2, p_label VARCHAR2, p_key_length PLS_INTEGER DEFAULT 16) RETURN RAW IS
    l_raw RAW(32767);
  BEGIN
    l_raw := UTL_I18N.STRING_TO_RAW(p_value, 'AL32UTF8');
    IF NVL(UTL_RAW.LENGTH(l_raw), 0) != p_key_length THEN
      RAISE_APPLICATION_ERROR(-20010, p_label || ' deve conter exatamente ' || p_key_length || ' bytes UTF-8.');
    END IF;
    RETURN l_raw;
  END aes_key_raw;

  FUNCTION aes_string_blob(p_text VARCHAR2) RETURN BLOB IS
    l_blob BLOB;
    l_raw RAW(32767);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    l_raw := UTL_I18N.STRING_TO_RAW(p_text, 'AL32UTF8');
    IF l_raw IS NOT NULL THEN
      DBMS_LOB.WRITEAPPEND(l_blob, UTL_RAW.LENGTH(l_raw), l_raw);
    END IF;
    RETURN l_blob;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_blob);
      END IF;
      RAISE;
  END aes_string_blob;

  FUNCTION aes_encrypt_text_hex(
    p_text VARCHAR2,
    p_key_text VARCHAR2,
    p_iv_text VARCHAR2,
    p_key_length PLS_INTEGER
  ) RETURN VARCHAR2 IS
    l_plain BLOB;
    l_cipher BLOB;
    l_hex CLOB;
    l_result VARCHAR2(32767);
  BEGIN
    l_plain := aes_string_blob(p_text);
    l_cipher := aes_encrypt_blob(
      l_plain,
      aes_key_raw(p_key_text, 'Chave AES', p_key_length),
      aes_key_raw(p_iv_text, 'IV'),
      p_key_length
    );
    l_hex := aes_hex_blob(l_cipher);
    IF DBMS_LOB.GETLENGTH(l_hex) > 32767 THEN
      RAISE_APPLICATION_ERROR(-20016, 'Ciphertext excede o limite VARCHAR2; use a sobrecarga CLOB.');
    END IF;
    l_result := DBMS_LOB.SUBSTR(l_hex, 32767, 1);
    DBMS_LOB.FREETEMPORARY(l_plain);
    DBMS_LOB.FREETEMPORARY(l_cipher);
    DBMS_LOB.FREETEMPORARY(l_hex);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_plain) = 1 THEN DBMS_LOB.FREETEMPORARY(l_plain); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_cipher) = 1 THEN DBMS_LOB.FREETEMPORARY(l_cipher); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_hex) = 1 THEN DBMS_LOB.FREETEMPORARY(l_hex); END IF;
      RAISE;
  END aes_encrypt_text_hex;

  FUNCTION hash_blob_internal(p_data BLOB) RETURN VARCHAR2 IS
    c_hex CONSTANT VARCHAR2(16) := '0123456789ABCDEF';
    TYPE t_word_array IS TABLE OF NUMBER INDEX BY PLS_INTEGER;
    TYPE t_int_array IS TABLE OF PLS_INTEGER INDEX BY PLS_INTEGER;
    l_shift t_int_array;
    l_k t_word_array;
    l_words t_word_array;
    l_a0 NUMBER := 1732584193;
    l_b0 NUMBER := 4023233417;
    l_c0 NUMBER := 2562383102;
    l_d0 NUMBER := 271733878;
    l_length NUMBER := 0;
    l_offset NUMBER := 1;
    l_block RAW(64);
    l_tail RAW(128);
    l_tail_length PLS_INTEGER;
    l_padding_length PLS_INTEGER;
    l_byte NUMBER;
    l_a NUMBER;
    l_b NUMBER;
    l_c NUMBER;
    l_d NUMBER;
    l_f NUMBER;
    l_g PLS_INTEGER;
    l_temp NUMBER;
    l_hex VARCHAR2(32);

    FUNCTION byte_value(p_raw RAW, p_position PLS_INTEGER) RETURN NUMBER IS
      l_hex_byte VARCHAR2(2);
    BEGIN
      l_hex_byte := RAWTOHEX(UTL_RAW.SUBSTR(p_raw, p_position, 1));
      RETURN (INSTR(c_hex, SUBSTR(l_hex_byte, 1, 1)) - 1) * 16
           + INSTR(c_hex, SUBSTR(l_hex_byte, 2, 1)) - 1;
    END byte_value;

    FUNCTION byte_hex(p_value NUMBER) RETURN VARCHAR2 IS
    BEGIN
      RETURN SUBSTR(c_hex, TRUNC(p_value / 16) + 1, 1)
          || SUBSTR(c_hex, MOD(p_value, 16) + 1, 1);
    END byte_hex;

    PROCEDURE process_block(p_block RAW) IS
    BEGIN
      FOR j IN 0 .. 15 LOOP
        l_words(j) := byte_value(p_block, j * 4 + 1)
                    + byte_value(p_block, j * 4 + 2) * 256
                    + byte_value(p_block, j * 4 + 3) * 65536
                    + byte_value(p_block, j * 4 + 4) * 16777216;
      END LOOP;

      l_a := l_a0;
      l_b := l_b0;
      l_c := l_c0;
      l_d := l_d0;

      FOR j IN 0 .. 63 LOOP
        IF j < 16 THEN
          l_f := bit_or32(bit_and32(l_b, l_c), bit_and32(c_mod32 - 1 - l_b, l_d));
          l_g := j;
        ELSIF j < 32 THEN
          l_f := bit_or32(bit_and32(l_b, l_d), bit_and32(l_c, c_mod32 - 1 - l_d));
          l_g := MOD(5 * j + 1, 16);
        ELSIF j < 48 THEN
          l_f := bit_xor32(bit_xor32(l_b, l_c), l_d);
          l_g := MOD(3 * j + 5, 16);
        ELSE
          l_f := bit_xor32(l_c, bit_or32(l_b, c_mod32 - 1 - l_d));
          l_g := MOD(7 * j, 16);
        END IF;

        l_temp := l_d;
        l_d := l_c;
        l_c := l_b;
        l_b := MOD(l_b + rotate_left32(
          MOD(l_a + l_f + l_k(j) + l_words(l_g), c_mod32), l_shift(j)
        ), c_mod32);
        l_a := l_temp;
      END LOOP;

      l_a0 := MOD(l_a0 + l_a, c_mod32);
      l_b0 := MOD(l_b0 + l_b, c_mod32);
      l_c0 := MOD(l_c0 + l_c, c_mod32);
      l_d0 := MOD(l_d0 + l_d, c_mod32);
    END process_block;

    FUNCTION word_hex(p_word NUMBER) RETURN VARCHAR2 IS
    BEGIN
      RETURN byte_hex(MOD(TRUNC(p_word / 1), 256)) ||
             byte_hex(MOD(TRUNC(p_word / 256), 256)) ||
             byte_hex(MOD(TRUNC(p_word / 65536), 256)) ||
             byte_hex(MOD(TRUNC(p_word / 16777216), 256));
    END word_hex;
  BEGIN
    l_shift(0) := 7;  l_shift(1) := 12; l_shift(2) := 17; l_shift(3) := 22;
    l_shift(4) := 7;  l_shift(5) := 12; l_shift(6) := 17; l_shift(7) := 22;
    l_shift(8) := 7;  l_shift(9) := 12; l_shift(10) := 17; l_shift(11) := 22;
    l_shift(12) := 7; l_shift(13) := 12; l_shift(14) := 17; l_shift(15) := 22;
    l_shift(16) := 5; l_shift(17) := 9;  l_shift(18) := 14; l_shift(19) := 20;
    l_shift(20) := 5; l_shift(21) := 9;  l_shift(22) := 14; l_shift(23) := 20;
    l_shift(24) := 5; l_shift(25) := 9;  l_shift(26) := 14; l_shift(27) := 20;
    l_shift(28) := 5; l_shift(29) := 9;  l_shift(30) := 14; l_shift(31) := 20;
    l_shift(32) := 4; l_shift(33) := 11; l_shift(34) := 16; l_shift(35) := 23;
    l_shift(36) := 4; l_shift(37) := 11; l_shift(38) := 16; l_shift(39) := 23;
    l_shift(40) := 4; l_shift(41) := 11; l_shift(42) := 16; l_shift(43) := 23;
    l_shift(44) := 4; l_shift(45) := 11; l_shift(46) := 16; l_shift(47) := 23;
    l_shift(48) := 6; l_shift(49) := 10; l_shift(50) := 15; l_shift(51) := 21;
    l_shift(52) := 6; l_shift(53) := 10; l_shift(54) := 15; l_shift(55) := 21;
    l_shift(56) := 6; l_shift(57) := 10; l_shift(58) := 15; l_shift(59) := 21;
    l_shift(60) := 6; l_shift(61) := 10; l_shift(62) := 15; l_shift(63) := 21;

    l_k(0) := 3614090360;  l_k(1) := 3905402710;  l_k(2) := 606105819;   l_k(3) := 3250441966;
    l_k(4) := 4118548399;  l_k(5) := 1200080426;  l_k(6) := 2821735955;  l_k(7) := 4249261313;
    l_k(8) := 1770035416;  l_k(9) := 2336552879;  l_k(10) := 4294925233; l_k(11) := 2304563134;
    l_k(12) := 1804603682; l_k(13) := 4254626195; l_k(14) := 2792965006; l_k(15) := 1236535329;
    l_k(16) := 4129170786; l_k(17) := 3225465664; l_k(18) := 643717713;  l_k(19) := 3921069994;
    l_k(20) := 3593408605; l_k(21) := 38016083;   l_k(22) := 3634488961; l_k(23) := 3889429448;
    l_k(24) := 568446438;  l_k(25) := 3275163606; l_k(26) := 4107603335; l_k(27) := 1163531501;
    l_k(28) := 2850285829; l_k(29) := 4243563512; l_k(30) := 1735328473; l_k(31) := 2368359562;
    l_k(32) := 4294588738; l_k(33) := 2272392833; l_k(34) := 1839030562; l_k(35) := 4259657740;
    l_k(36) := 2763975236; l_k(37) := 1272893353; l_k(38) := 4139469664; l_k(39) := 3200236656;
    l_k(40) := 681279174;  l_k(41) := 3936430074; l_k(42) := 3572445317; l_k(43) := 76029189;
    l_k(44) := 3654602809; l_k(45) := 3873151461; l_k(46) := 530742520;  l_k(47) := 3299628645;
    l_k(48) := 4096336452; l_k(49) := 1126891415; l_k(50) := 2878612391; l_k(51) := 4237533241;
    l_k(52) := 1700485571; l_k(53) := 2399980690; l_k(54) := 4293915773; l_k(55) := 2240044497;
    l_k(56) := 1873313359; l_k(57) := 4264355552; l_k(58) := 2734768916; l_k(59) := 1309151649;
    l_k(60) := 4149444226; l_k(61) := 3174756917; l_k(62) := 718787259;  l_k(63) := 3951481745;

    IF p_data IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_data);
      WHILE l_offset + 63 <= l_length LOOP
        l_block := DBMS_LOB.SUBSTR(p_data, 64, l_offset);
        process_block(l_block);
        l_offset := l_offset + 64;
      END LOOP;
    END IF;

    IF p_data IS NOT NULL THEN
      l_tail := DBMS_LOB.SUBSTR(p_data, 64, l_offset);
    END IF;
    l_tail_length := NVL(UTL_RAW.LENGTH(l_tail), 0);
    IF l_tail_length = 0 THEN
      l_tail := HEXTORAW('80');
    ELSE
      l_tail := UTL_RAW.CONCAT(l_tail, HEXTORAW('80'));
    END IF;
    IF l_tail_length + 1 > 56 THEN
      l_padding_length := 64 - UTL_RAW.LENGTH(l_tail);
      IF l_padding_length > 0 THEN
        l_tail := UTL_RAW.CONCAT(l_tail, HEXTORAW(RPAD('0', l_padding_length * 2, '0')));
      END IF;
      process_block(l_tail);
      l_tail := HEXTORAW(RPAD('0', 112, '0'));
    END IF;
    l_padding_length := 56 - UTL_RAW.LENGTH(l_tail);
    IF l_padding_length > 0 THEN
      l_tail := UTL_RAW.CONCAT(l_tail, HEXTORAW(RPAD('0', l_padding_length * 2, '0')));
    END IF;

    FOR j IN 0 .. 7 LOOP
      l_byte := MOD(TRUNC(l_length * 8 / POWER(256, j)), 256);
      l_tail := UTL_RAW.CONCAT(l_tail, HEXTORAW(byte_hex(l_byte)));
    END LOOP;
    process_block(l_tail);

    l_hex := word_hex(l_a0) || word_hex(l_b0) || word_hex(l_c0) || word_hex(l_d0);
    RETURN LOWER(l_hex);
  END hash_blob_internal;

  FUNCTION hash_blob_sha1_internal(p_data BLOB) RETURN VARCHAR2 IS
    c_hex CONSTANT VARCHAR2(16) := '0123456789ABCDEF';
    TYPE t_word_array IS TABLE OF NUMBER INDEX BY PLS_INTEGER;
    l_words t_word_array;
    l_h0 NUMBER := 1732584193;
    l_h1 NUMBER := 4023233417;
    l_h2 NUMBER := 2562383102;
    l_h3 NUMBER := 271733878;
    l_h4 NUMBER := 3285377520;
    l_length NUMBER := 0;
    l_offset NUMBER := 1;
    l_block RAW(64);
    l_tail RAW(128);
    l_tail_length PLS_INTEGER;
    l_padding_length PLS_INTEGER;
    l_a NUMBER;
    l_b NUMBER;
    l_c NUMBER;
    l_d NUMBER;
    l_e NUMBER;
    l_f NUMBER;
    l_k NUMBER;
    l_temp NUMBER;
    l_hex VARCHAR2(40);

    FUNCTION byte_value(p_raw RAW, p_position PLS_INTEGER) RETURN NUMBER IS
      l_hex_byte VARCHAR2(2);
    BEGIN
      l_hex_byte := RAWTOHEX(UTL_RAW.SUBSTR(p_raw, p_position, 1));
      RETURN (INSTR(c_hex, SUBSTR(l_hex_byte, 1, 1)) - 1) * 16
           + INSTR(c_hex, SUBSTR(l_hex_byte, 2, 1)) - 1;
    END byte_value;

    FUNCTION byte_hex(p_value NUMBER) RETURN VARCHAR2 IS
    BEGIN
      RETURN SUBSTR(c_hex, TRUNC(p_value / 16) + 1, 1)
          || SUBSTR(c_hex, MOD(p_value, 16) + 1, 1);
    END byte_hex;

    PROCEDURE process_block(p_block RAW) IS
    BEGIN
      FOR j IN 0 .. 15 LOOP
        l_words(j) := byte_value(p_block, j * 4 + 1) * 16777216
                    + byte_value(p_block, j * 4 + 2) * 65536
                    + byte_value(p_block, j * 4 + 3) * 256
                    + byte_value(p_block, j * 4 + 4);
      END LOOP;

      FOR j IN 16 .. 79 LOOP
        l_words(j) := rotate_left32(
          bit_xor32(bit_xor32(l_words(j - 3), l_words(j - 8)),
                    bit_xor32(l_words(j - 14), l_words(j - 16))),
          1
        );
      END LOOP;

      l_a := l_h0;
      l_b := l_h1;
      l_c := l_h2;
      l_d := l_h3;
      l_e := l_h4;

      FOR j IN 0 .. 79 LOOP
        IF j < 20 THEN
          l_f := bit_or32(bit_and32(l_b, l_c),
                          bit_and32(c_mod32 - 1 - l_b, l_d));
          l_k := 1518500249;
        ELSIF j < 40 THEN
          l_f := bit_xor32(bit_xor32(l_b, l_c), l_d);
          l_k := 1859775393;
        ELSIF j < 60 THEN
          l_f := bit_or32(bit_or32(bit_and32(l_b, l_c), bit_and32(l_b, l_d)),
                          bit_and32(l_c, l_d));
          l_k := 2400959708;
        ELSE
          l_f := bit_xor32(bit_xor32(l_b, l_c), l_d);
          l_k := 3395469782;
        END IF;

        l_temp := MOD(rotate_left32(l_a, 5) + l_f + l_e + l_k + l_words(j), c_mod32);
        l_e := l_d;
        l_d := l_c;
        l_c := rotate_left32(l_b, 30);
        l_b := l_a;
        l_a := l_temp;
      END LOOP;

      l_h0 := MOD(l_h0 + l_a, c_mod32);
      l_h1 := MOD(l_h1 + l_b, c_mod32);
      l_h2 := MOD(l_h2 + l_c, c_mod32);
      l_h3 := MOD(l_h3 + l_d, c_mod32);
      l_h4 := MOD(l_h4 + l_e, c_mod32);
    END process_block;

    FUNCTION word_hex(p_word NUMBER) RETURN VARCHAR2 IS
    BEGIN
      RETURN byte_hex(MOD(TRUNC(p_word / 16777216), 256)) ||
             byte_hex(MOD(TRUNC(p_word / 65536), 256)) ||
             byte_hex(MOD(TRUNC(p_word / 256), 256)) ||
             byte_hex(MOD(p_word, 256));
    END word_hex;
  BEGIN
    IF p_data IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_data);
      WHILE l_offset + 63 <= l_length LOOP
        l_block := DBMS_LOB.SUBSTR(p_data, 64, l_offset);
        process_block(l_block);
        l_offset := l_offset + 64;
      END LOOP;
      l_tail := DBMS_LOB.SUBSTR(p_data, 64, l_offset);
    END IF;

    l_tail_length := NVL(UTL_RAW.LENGTH(l_tail), 0);
    IF l_tail_length = 0 THEN
      l_tail := HEXTORAW('80');
    ELSE
      l_tail := UTL_RAW.CONCAT(l_tail, HEXTORAW('80'));
    END IF;

    IF l_tail_length + 1 > 56 THEN
      l_padding_length := 64 - UTL_RAW.LENGTH(l_tail);
      IF l_padding_length > 0 THEN
        l_tail := UTL_RAW.CONCAT(l_tail, HEXTORAW(RPAD('0', l_padding_length * 2, '0')));
      END IF;
      process_block(l_tail);
      l_tail := HEXTORAW(RPAD('0', 112, '0'));
    END IF;

    l_padding_length := 56 - UTL_RAW.LENGTH(l_tail);
    IF l_padding_length > 0 THEN
      l_tail := UTL_RAW.CONCAT(l_tail, HEXTORAW(RPAD('0', l_padding_length * 2, '0')));
    END IF;
    FOR j IN REVERSE 0 .. 7 LOOP
      l_tail := UTL_RAW.CONCAT(
        l_tail,
        HEXTORAW(byte_hex(MOD(TRUNC(l_length * 8 / POWER(256, j)), 256)))
      );
    END LOOP;
    process_block(l_tail);

    l_hex := word_hex(l_h0) || word_hex(l_h1) || word_hex(l_h2) ||
             word_hex(l_h3) || word_hex(l_h4);
    RETURN LOWER(l_hex);
  END hash_blob_sha1_internal;

  FUNCTION hash_blob_sha256_internal(p_data BLOB) RETURN VARCHAR2 IS
    c_hex CONSTANT VARCHAR2(16) := '0123456789ABCDEF';
    TYPE t_word_array IS TABLE OF NUMBER INDEX BY PLS_INTEGER;
    l_words t_word_array;
    l_k t_word_array;
    l_h0 NUMBER := 1779033703;
    l_h1 NUMBER := 3144134277;
    l_h2 NUMBER := 1013904242;
    l_h3 NUMBER := 2773480762;
    l_h4 NUMBER := 1359893119;
    l_h5 NUMBER := 2600822924;
    l_h6 NUMBER := 528734635;
    l_h7 NUMBER := 1541459225;
    l_length NUMBER := 0;
    l_offset NUMBER := 1;
    l_block RAW(64);
    l_tail RAW(128);
    l_tail_length PLS_INTEGER;
    l_padding_length PLS_INTEGER;
    l_a NUMBER;
    l_b NUMBER;
    l_c NUMBER;
    l_d NUMBER;
    l_e NUMBER;
    l_f NUMBER;
    l_g NUMBER;
    l_h NUMBER;
    l_s0 NUMBER;
    l_s1 NUMBER;
    l_choice NUMBER;
    l_majority NUMBER;
    l_temp1 NUMBER;
    l_temp2 NUMBER;
    l_hex VARCHAR2(64);

    FUNCTION byte_value(p_raw RAW, p_position PLS_INTEGER) RETURN NUMBER IS
      l_hex_byte VARCHAR2(2);
    BEGIN
      l_hex_byte := RAWTOHEX(UTL_RAW.SUBSTR(p_raw, p_position, 1));
      RETURN (INSTR(c_hex, SUBSTR(l_hex_byte, 1, 1)) - 1) * 16
           + INSTR(c_hex, SUBSTR(l_hex_byte, 2, 1)) - 1;
    END byte_value;

    FUNCTION byte_hex(p_value NUMBER) RETURN VARCHAR2 IS
    BEGIN
      RETURN SUBSTR(c_hex, TRUNC(p_value / 16) + 1, 1)
          || SUBSTR(c_hex, MOD(p_value, 16) + 1, 1);
    END byte_hex;

    PROCEDURE process_block(p_block RAW) IS
    BEGIN
      FOR j IN 0 .. 15 LOOP
        l_words(j) := byte_value(p_block, j * 4 + 1) * 16777216
                    + byte_value(p_block, j * 4 + 2) * 65536
                    + byte_value(p_block, j * 4 + 3) * 256
                    + byte_value(p_block, j * 4 + 4);
      END LOOP;

      FOR j IN 16 .. 63 LOOP
        l_s0 := bit_xor32(
          bit_xor32(rotate_left32(l_words(j - 15), 25),
                    rotate_left32(l_words(j - 15), 14)),
          TRUNC(l_words(j - 15) / 8)
        );
        l_s1 := bit_xor32(
          bit_xor32(rotate_left32(l_words(j - 2), 15),
                    rotate_left32(l_words(j - 2), 13)),
          TRUNC(l_words(j - 2) / 1024)
        );
        l_words(j) := MOD(l_words(j - 16) + l_s0 + l_words(j - 7) + l_s1, c_mod32);
      END LOOP;

      l_a := l_h0; l_b := l_h1; l_c := l_h2; l_d := l_h3;
      l_e := l_h4; l_f := l_h5; l_g := l_h6; l_h := l_h7;

      FOR j IN 0 .. 63 LOOP
        l_s1 := bit_xor32(
          bit_xor32(rotate_left32(l_e, 26), rotate_left32(l_e, 21)),
          rotate_left32(l_e, 7)
        );
        l_choice := bit_xor32(bit_and32(l_e, l_f),
                              bit_and32(c_mod32 - 1 - l_e, l_g));
        l_temp1 := MOD(l_h + l_s1 + l_choice + l_k(j) + l_words(j), c_mod32);
        l_s0 := bit_xor32(
          bit_xor32(rotate_left32(l_a, 30), rotate_left32(l_a, 19)),
          rotate_left32(l_a, 10)
        );
        l_majority := bit_xor32(
          bit_xor32(bit_and32(l_a, l_b), bit_and32(l_a, l_c)),
          bit_and32(l_b, l_c)
        );
        l_temp2 := MOD(l_s0 + l_majority, c_mod32);

        l_h := l_g; l_g := l_f; l_f := l_e;
        l_e := MOD(l_d + l_temp1, c_mod32);
        l_d := l_c; l_c := l_b; l_b := l_a;
        l_a := MOD(l_temp1 + l_temp2, c_mod32);
      END LOOP;

      l_h0 := MOD(l_h0 + l_a, c_mod32);
      l_h1 := MOD(l_h1 + l_b, c_mod32);
      l_h2 := MOD(l_h2 + l_c, c_mod32);
      l_h3 := MOD(l_h3 + l_d, c_mod32);
      l_h4 := MOD(l_h4 + l_e, c_mod32);
      l_h5 := MOD(l_h5 + l_f, c_mod32);
      l_h6 := MOD(l_h6 + l_g, c_mod32);
      l_h7 := MOD(l_h7 + l_h, c_mod32);
    END process_block;

    FUNCTION word_hex(p_word NUMBER) RETURN VARCHAR2 IS
    BEGIN
      RETURN byte_hex(MOD(TRUNC(p_word / 16777216), 256)) ||
             byte_hex(MOD(TRUNC(p_word / 65536), 256)) ||
             byte_hex(MOD(TRUNC(p_word / 256), 256)) ||
             byte_hex(MOD(p_word, 256));
    END word_hex;
  BEGIN
    l_k(0) := 1116352408; l_k(1) := 1899447441; l_k(2) := 3049323471; l_k(3) := 3921009573;
    l_k(4) := 961987163;  l_k(5) := 1508970993; l_k(6) := 2453635748; l_k(7) := 2870763221;
    l_k(8) := 3624381080; l_k(9) := 310598401;  l_k(10) := 607225278; l_k(11) := 1426881987;
    l_k(12) := 1925078388; l_k(13) := 2162078206; l_k(14) := 2614888103; l_k(15) := 3248222580;
    l_k(16) := 3835390401; l_k(17) := 4022224774; l_k(18) := 264347078;  l_k(19) := 604807628;
    l_k(20) := 770255983;  l_k(21) := 1249150122; l_k(22) := 1555081692; l_k(23) := 1996064986;
    l_k(24) := 2554220882; l_k(25) := 2821834349; l_k(26) := 2952996808; l_k(27) := 3210313671;
    l_k(28) := 3336571891; l_k(29) := 3584528711; l_k(30) := 113926993;  l_k(31) := 338241895;
    l_k(32) := 666307205;  l_k(33) := 773529912;  l_k(34) := 1294757372; l_k(35) := 1396182291;
    l_k(36) := 1695183700; l_k(37) := 1986661051; l_k(38) := 2177026350; l_k(39) := 2456956037;
    l_k(40) := 2730485921; l_k(41) := 2820302411; l_k(42) := 3259730800; l_k(43) := 3345764771;
    l_k(44) := 3516065817; l_k(45) := 3600352804; l_k(46) := 4094571909; l_k(47) := 275423344;
    l_k(48) := 430227734;  l_k(49) := 506948616;  l_k(50) := 659060556;  l_k(51) := 883997877;
    l_k(52) := 958139571;  l_k(53) := 1322822218; l_k(54) := 1537002063; l_k(55) := 1747873779;
    l_k(56) := 1955562222; l_k(57) := 2024104815; l_k(58) := 2227730452; l_k(59) := 2361852424;
    l_k(60) := 2428436474; l_k(61) := 2756734187; l_k(62) := 3204031479; l_k(63) := 3329325298;

    IF p_data IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_data);
      WHILE l_offset + 63 <= l_length LOOP
        l_block := DBMS_LOB.SUBSTR(p_data, 64, l_offset);
        process_block(l_block);
        l_offset := l_offset + 64;
      END LOOP;
      l_tail := DBMS_LOB.SUBSTR(p_data, 64, l_offset);
    END IF;

    l_tail_length := NVL(UTL_RAW.LENGTH(l_tail), 0);
    IF l_tail_length = 0 THEN
      l_tail := HEXTORAW('80');
    ELSE
      l_tail := UTL_RAW.CONCAT(l_tail, HEXTORAW('80'));
    END IF;
    IF l_tail_length + 1 > 56 THEN
      l_padding_length := 64 - UTL_RAW.LENGTH(l_tail);
      IF l_padding_length > 0 THEN
        l_tail := UTL_RAW.CONCAT(l_tail, HEXTORAW(RPAD('0', l_padding_length * 2, '0')));
      END IF;
      process_block(l_tail);
      l_tail := HEXTORAW(RPAD('0', 112, '0'));
    END IF;
    l_padding_length := 56 - UTL_RAW.LENGTH(l_tail);
    IF l_padding_length > 0 THEN
      l_tail := UTL_RAW.CONCAT(l_tail, HEXTORAW(RPAD('0', l_padding_length * 2, '0')));
    END IF;
    FOR j IN REVERSE 0 .. 7 LOOP
      l_tail := UTL_RAW.CONCAT(
        l_tail,
        HEXTORAW(byte_hex(MOD(TRUNC(l_length * 8 / POWER(256, j)), 256)))
      );
    END LOOP;
    process_block(l_tail);

    l_hex := word_hex(l_h0) || word_hex(l_h1) || word_hex(l_h2) || word_hex(l_h3) ||
             word_hex(l_h4) || word_hex(l_h5) || word_hex(l_h6) || word_hex(l_h7);
    RETURN LOWER(l_hex);
  END hash_blob_sha256_internal;

  FUNCTION sha3_xor64(p_a NUMBER, p_b NUMBER) RETURN NUMBER IS
    l_a NUMBER := p_a;
    l_b NUMBER := p_b;
    l_result NUMBER := 0;
    l_place NUMBER := 1;
  BEGIN
    FOR i IN 1 .. 64 LOOP
      IF MOD(l_a, 2) <> MOD(l_b, 2) THEN
        l_result := l_result + l_place;
      END IF;
      l_a := TRUNC(l_a / 2);
      l_b := TRUNC(l_b / 2);
      l_place := l_place * 2;
    END LOOP;
    RETURN l_result;
  END sha3_xor64;

  FUNCTION rotate_left64(p_value NUMBER, p_bits PLS_INTEGER) RETURN NUMBER IS
    l_power NUMBER := POWER(2, p_bits);
  BEGIN
    RETURN MOD(
      MOD(p_value, POWER(2, 64 - p_bits)) * l_power +
      TRUNC(p_value / POWER(2, 64 - p_bits)),
      18446744073709551616
    );
  END rotate_left64;

  FUNCTION hash_blob_sha3_internal(p_data BLOB, p_digest_bytes PLS_INTEGER) RETURN VARCHAR2 IS
    c_hex CONSTANT VARCHAR2(16) := '0123456789ABCDEF';
    c_mask64 CONSTANT NUMBER := 18446744073709551615;
    l_rate_bytes PLS_INTEGER := 200 - 2 * p_digest_bytes;
    TYPE t_lane_array IS TABLE OF NUMBER INDEX BY PLS_INTEGER;
    l_state t_lane_array;
    l_length NUMBER := 0;
    l_offset NUMBER := 1;
    l_block RAW(200);
    l_tail RAW(200);
    l_tail_length PLS_INTEGER;
    l_byte PLS_INTEGER;
    l_lane NUMBER;
    l_hex VARCHAR2(128);

    FUNCTION byte_value(p_raw RAW, p_position PLS_INTEGER) RETURN PLS_INTEGER IS
      l_hex_byte VARCHAR2(2);
    BEGIN
      l_hex_byte := RAWTOHEX(UTL_RAW.SUBSTR(p_raw, p_position, 1));
      RETURN (INSTR(c_hex, SUBSTR(l_hex_byte, 1, 1)) - 1) * 16
           + INSTR(c_hex, SUBSTR(l_hex_byte, 2, 1)) - 1;
    END byte_value;

    FUNCTION byte_hex(p_value PLS_INTEGER) RETURN VARCHAR2 IS
    BEGIN
      RETURN SUBSTR(c_hex, TRUNC(p_value / 16) + 1, 1)
          || SUBSTR(c_hex, MOD(p_value, 16) + 1, 1);
    END byte_hex;

    FUNCTION lane_and64(p_a NUMBER, p_b NUMBER) RETURN NUMBER IS
      l_a NUMBER := p_a;
      l_b NUMBER := p_b;
      l_result NUMBER := 0;
      l_place NUMBER := 1;
    BEGIN
      FOR bit_index IN 1 .. 64 LOOP
        IF MOD(l_a, 2) = 1 AND MOD(l_b, 2) = 1 THEN
          l_result := l_result + l_place;
        END IF;
        l_a := TRUNC(l_a / 2);
        l_b := TRUNC(l_b / 2);
        l_place := l_place * 2;
      END LOOP;
      RETURN l_result;
    END lane_and64;

    PROCEDURE permute_state IS
      TYPE t_round_constants IS TABLE OF VARCHAR2(16) INDEX BY PLS_INTEGER;
      l_rc_hex t_round_constants;
      l_rc NUMBER;
      l_c t_lane_array;
      l_d t_lane_array;
      l_b t_lane_array;
      l_theta NUMBER;
      l_rho PLS_INTEGER;
      l_x PLS_INTEGER;
      l_y PLS_INTEGER;
      l_index PLS_INTEGER;
      l_hex_digit VARCHAR2(1);
    BEGIN
      l_rc_hex(0)  := '0000000000000001';
      l_rc_hex(1)  := '0000000000008082';
      l_rc_hex(2)  := '800000000000808A';
      l_rc_hex(3)  := '8000000080008000';
      l_rc_hex(4)  := '000000000000808B';
      l_rc_hex(5)  := '0000000080000001';
      l_rc_hex(6)  := '8000000080008081';
      l_rc_hex(7)  := '8000000000008009';
      l_rc_hex(8)  := '000000000000008A';
      l_rc_hex(9)  := '0000000000000088';
      l_rc_hex(10) := '0000000080008009';
      l_rc_hex(11) := '000000008000000A';
      l_rc_hex(12) := '000000008000808B';
      l_rc_hex(13) := '800000000000008B';
      l_rc_hex(14) := '8000000000008089';
      l_rc_hex(15) := '8000000000008003';
      l_rc_hex(16) := '8000000000008002';
      l_rc_hex(17) := '8000000000000080';
      l_rc_hex(18) := '000000000000800A';
      l_rc_hex(19) := '800000008000000A';
      l_rc_hex(20) := '8000000080008081';
      l_rc_hex(21) := '8000000000008080';
      l_rc_hex(22) := '0000000080000001';
      l_rc_hex(23) := '8000000080008008';

      FOR round_index IN 0 .. 23 LOOP
        -- Theta.
        FOR x IN 0 .. 4 LOOP
          l_c(x) := 0;
          FOR y IN 0 .. 4 LOOP
            l_c(x) := sha3_xor64(l_c(x), l_state(x + 5 * y));
          END LOOP;
        END LOOP;
        FOR x IN 0 .. 4 LOOP
          l_d(x) := sha3_xor64(l_c(MOD(x + 4, 5)), rotate_left64(l_c(MOD(x + 1, 5)), 1));
        END LOOP;
        FOR x IN 0 .. 4 LOOP
          FOR y IN 0 .. 4 LOOP
            l_index := x + 5 * y;
            l_state(l_index) := sha3_xor64(l_state(l_index), l_d(x));
          END LOOP;
        END LOOP;

        -- Rho and Pi.
        l_b(0) := l_state(0);
        l_rho := 1;
        l_x := 1;
        l_y := 0;
        FOR t IN 0 .. 23 LOOP
          l_index := l_x + 5 * l_y;
          l_b(l_y + 5 * MOD(2 * l_x + 3 * l_y, 5)) := rotate_left64(l_state(l_index), l_rho);
          -- Atribui ao próximo lane o deslocamento triangular seguinte.
          l_rho := MOD((t + 2) * (t + 3) / 2, 64);
          l_index := l_x;
          l_x := l_y;
          l_y := MOD(2 * l_index + 3 * l_y, 5);
        END LOOP;

        -- Chi.
        FOR x IN 0 .. 4 LOOP
          FOR y IN 0 .. 4 LOOP
            l_index := x + 5 * y;
            l_state(l_index) := sha3_xor64(
              l_b(l_index),
              lane_and64(
                c_mask64 - NVL(l_b(MOD(x + 1, 5) + 5 * y), 0),
                NVL(l_b(MOD(x + 2, 5) + 5 * y), 0)
              )
            );
          END LOOP;
        END LOOP;

        -- Iota: round constants are stored as hexadecimal to avoid decimal precision loss.
        l_rc := 0;
        FOR digit_index IN 1 .. 16 LOOP
          l_hex_digit := SUBSTR(l_rc_hex(round_index), digit_index, 1);
          l_rc := l_rc * 16 + INSTR(c_hex, l_hex_digit) - 1;
        END LOOP;
        l_state(0) := sha3_xor64(l_state(0), l_rc);
      END LOOP;
    END permute_state;
  BEGIN
    FOR i IN 0 .. 24 LOOP
      l_state(i) := 0;
    END LOOP;

    IF p_data IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_data);
      WHILE l_offset + l_rate_bytes - 1 <= l_length LOOP
        l_block := DBMS_LOB.SUBSTR(p_data, l_rate_bytes, l_offset);
        FOR i IN 0 .. l_rate_bytes - 1 LOOP
          l_byte := byte_value(l_block, i + 1);
          l_lane := TRUNC(i / 8);
          l_state(l_lane) := sha3_xor64(
            NVL(l_state(l_lane), 0),
            l_byte * POWER(256, MOD(i, 8))
          );
        END LOOP;
        permute_state;
        l_offset := l_offset + l_rate_bytes;
      END LOOP;
      l_tail := DBMS_LOB.SUBSTR(p_data, l_rate_bytes, l_offset);
    END IF;

    l_tail_length := NVL(UTL_RAW.LENGTH(l_tail), 0);
    FOR i IN 0 .. l_tail_length - 1 LOOP
      l_byte := byte_value(l_tail, i + 1);
      l_lane := TRUNC(i / 8);
      l_state(l_lane) := sha3_xor64(
        NVL(l_state(l_lane), 0),
        l_byte * POWER(256, MOD(i, 8))
      );
    END LOOP;
    -- SHA3 domain separation suffix 0x06 and final rate bit 0x80.
    l_lane := TRUNC(l_tail_length / 8);
    l_state(l_lane) := sha3_xor64(
      NVL(l_state(l_lane), 0),
      6 * POWER(256, MOD(l_tail_length, 8))
    );
    l_lane := TRUNC((l_rate_bytes - 1) / 8);
    l_state(l_lane) := sha3_xor64(
      NVL(l_state(l_lane), 0),
      128 * POWER(256, MOD(l_rate_bytes - 1, 8))
    );
    permute_state;

    FOR i IN 0 .. p_digest_bytes - 1 LOOP
      l_lane := TRUNC(i / 8);
      l_byte := MOD(TRUNC(l_state(l_lane) / POWER(256, MOD(i, 8))), 256);
      l_hex := l_hex || byte_hex(l_byte);
    END LOOP;
    RETURN LOWER(l_hex);
  END hash_blob_sha3_internal;

  FUNCTION bit_and64(p_a NUMBER, p_b NUMBER) RETURN NUMBER IS
    l_a NUMBER := p_a;
    l_b NUMBER := p_b;
    l_result NUMBER := 0;
    l_place NUMBER := 1;
  BEGIN
    FOR i IN 1 .. 64 LOOP
      IF MOD(l_a, 2) = 1 AND MOD(l_b, 2) = 1 THEN
        l_result := l_result + l_place;
      END IF;
      l_a := TRUNC(l_a / 2);
      l_b := TRUNC(l_b / 2);
      l_place := l_place * 2;
    END LOOP;
    RETURN l_result;
  END bit_and64;

  FUNCTION bit_xor64(p_a NUMBER, p_b NUMBER) RETURN NUMBER IS
    l_a NUMBER := p_a;
    l_b NUMBER := p_b;
    l_result NUMBER := 0;
    l_place NUMBER := 1;
  BEGIN
    FOR i IN 1 .. 64 LOOP
      IF MOD(l_a, 2) <> MOD(l_b, 2) THEN
        l_result := l_result + l_place;
      END IF;
      l_a := TRUNC(l_a / 2);
      l_b := TRUNC(l_b / 2);
      l_place := l_place * 2;
    END LOOP;
    RETURN l_result;
  END bit_xor64;

  FUNCTION rotate_right64(p_value NUMBER, p_bits PLS_INTEGER) RETURN NUMBER IS
    l_power NUMBER := POWER(2, p_bits);
  BEGIN
    RETURN TRUNC(p_value / l_power)
         + MOD(p_value, l_power) * POWER(2, 64 - p_bits);
  END rotate_right64;

  FUNCTION hash_blob_sha384_internal(
    p_data BLOB,
    p_sha512 BOOLEAN DEFAULT FALSE
  ) RETURN VARCHAR2 IS
    c_hex CONSTANT VARCHAR2(16) := '0123456789ABCDEF';
    c_mod64 CONSTANT NUMBER := 18446744073709551616;
    TYPE t_word_array IS TABLE OF NUMBER INDEX BY PLS_INTEGER;
    TYPE t_hex_array IS TABLE OF VARCHAR2(16) INDEX BY PLS_INTEGER;
    l_words t_word_array;
    l_k t_word_array;
    l_k_hex t_hex_array;
    l_h0 NUMBER;
    l_h1 NUMBER;
    l_h2 NUMBER;
    l_h3 NUMBER;
    l_h4 NUMBER;
    l_h5 NUMBER;
    l_h6 NUMBER;
    l_h7 NUMBER;
    l_length NUMBER := 0;
    l_offset NUMBER := 1;
    l_block RAW(128);
    l_tail RAW(256);
    l_tail_length PLS_INTEGER;
    l_padding_length PLS_INTEGER;
    l_a NUMBER;
    l_b NUMBER;
    l_c NUMBER;
    l_d NUMBER;
    l_e NUMBER;
    l_f NUMBER;
    l_g NUMBER;
    l_h NUMBER;
    l_s0 NUMBER;
    l_s1 NUMBER;
    l_choice NUMBER;
    l_majority NUMBER;
    l_temp1 NUMBER;
    l_temp2 NUMBER;
    l_hex VARCHAR2(128);

    FUNCTION hex_to_number(p_hex VARCHAR2) RETURN NUMBER IS
      l_value NUMBER := 0;
    BEGIN
      FOR i IN 1 .. LENGTH(p_hex) LOOP
        l_value := l_value * 16 + INSTR(c_hex, SUBSTR(UPPER(p_hex), i, 1)) - 1;
      END LOOP;
      RETURN l_value;
    END hex_to_number;

    FUNCTION byte_value(p_raw RAW, p_position PLS_INTEGER) RETURN NUMBER IS
      l_hex_byte VARCHAR2(2);
    BEGIN
      l_hex_byte := RAWTOHEX(UTL_RAW.SUBSTR(p_raw, p_position, 1));
      RETURN (INSTR(c_hex, SUBSTR(l_hex_byte, 1, 1)) - 1) * 16
           + INSTR(c_hex, SUBSTR(l_hex_byte, 2, 1)) - 1;
    END byte_value;

    FUNCTION byte_hex(p_value NUMBER) RETURN VARCHAR2 IS
    BEGIN
      RETURN SUBSTR(c_hex, TRUNC(p_value / 16) + 1, 1)
          || SUBSTR(c_hex, MOD(p_value, 16) + 1, 1);
    END byte_hex;

    PROCEDURE process_block(p_block RAW) IS
    BEGIN
      FOR j IN 0 .. 15 LOOP
        l_words(j) := byte_value(p_block, j * 8 + 1) * 72057594037927936
                    + byte_value(p_block, j * 8 + 2) * 281474976710656
                    + byte_value(p_block, j * 8 + 3) * 1099511627776
                    + byte_value(p_block, j * 8 + 4) * 4294967296
                    + byte_value(p_block, j * 8 + 5) * 16777216
                    + byte_value(p_block, j * 8 + 6) * 65536
                    + byte_value(p_block, j * 8 + 7) * 256
                    + byte_value(p_block, j * 8 + 8);
      END LOOP;

      FOR j IN 16 .. 79 LOOP
        l_s0 := bit_xor64(
          bit_xor64(rotate_right64(l_words(j - 15), 1),
                    rotate_right64(l_words(j - 15), 8)),
          TRUNC(l_words(j - 15) / 128)
        );
        l_s1 := bit_xor64(
          bit_xor64(rotate_right64(l_words(j - 2), 19),
                    rotate_right64(l_words(j - 2), 61)),
          TRUNC(l_words(j - 2) / 64)
        );
        l_words(j) := MOD(l_words(j - 16) + l_s0 + l_words(j - 7) + l_s1, c_mod64);
      END LOOP;

      l_a := l_h0; l_b := l_h1; l_c := l_h2; l_d := l_h3;
      l_e := l_h4; l_f := l_h5; l_g := l_h6; l_h := l_h7;

      FOR j IN 0 .. 79 LOOP
        l_s1 := bit_xor64(
          bit_xor64(rotate_right64(l_e, 14), rotate_right64(l_e, 18)),
          rotate_right64(l_e, 41)
        );
        l_choice := bit_xor64(bit_and64(l_e, l_f),
                              bit_and64(c_mod64 - 1 - l_e, l_g));
        l_temp1 := MOD(l_h + l_s1 + l_choice + l_k(j) + l_words(j), c_mod64);
        l_s0 := bit_xor64(
          bit_xor64(rotate_right64(l_a, 28), rotate_right64(l_a, 34)),
          rotate_right64(l_a, 39)
        );
        l_majority := bit_xor64(
          bit_xor64(bit_and64(l_a, l_b), bit_and64(l_a, l_c)),
          bit_and64(l_b, l_c)
        );
        l_temp2 := MOD(l_s0 + l_majority, c_mod64);

        l_h := l_g; l_g := l_f; l_f := l_e;
        l_e := MOD(l_d + l_temp1, c_mod64);
        l_d := l_c; l_c := l_b; l_b := l_a;
        l_a := MOD(l_temp1 + l_temp2, c_mod64);
      END LOOP;

      l_h0 := MOD(l_h0 + l_a, c_mod64);
      l_h1 := MOD(l_h1 + l_b, c_mod64);
      l_h2 := MOD(l_h2 + l_c, c_mod64);
      l_h3 := MOD(l_h3 + l_d, c_mod64);
      l_h4 := MOD(l_h4 + l_e, c_mod64);
      l_h5 := MOD(l_h5 + l_f, c_mod64);
      l_h6 := MOD(l_h6 + l_g, c_mod64);
      l_h7 := MOD(l_h7 + l_h, c_mod64);
    END process_block;

    FUNCTION word_hex(p_word NUMBER) RETURN VARCHAR2 IS
      l_hex_word VARCHAR2(16);
      l_value NUMBER := p_word;
    BEGIN
      FOR i IN REVERSE 1 .. 8 LOOP
        l_hex_word := byte_hex(MOD(l_value, 256)) || l_hex_word;
        l_value := TRUNC(l_value / 256);
      END LOOP;
      RETURN l_hex_word;
    END word_hex;
  BEGIN
    IF p_sha512 THEN
      l_h0 := hex_to_number('6A09E667F3BCC908');
      l_h1 := hex_to_number('BB67AE8584CAA73B');
      l_h2 := hex_to_number('3C6EF372FE94F82B');
      l_h3 := hex_to_number('A54FF53A5F1D36F1');
      l_h4 := hex_to_number('510E527FADE682D1');
      l_h5 := hex_to_number('9B05688C2B3E6C1F');
      l_h6 := hex_to_number('1F83D9ABFB41BD6B');
      l_h7 := hex_to_number('5BE0CD19137E2179');
    ELSE
      l_h0 := hex_to_number('CBBB9D5DC1059ED8');
      l_h1 := hex_to_number('629A292A367CD507');
      l_h2 := hex_to_number('9159015A3070DD17');
      l_h3 := hex_to_number('152FECD8F70E5939');
      l_h4 := hex_to_number('67332667FFC00B31');
      l_h5 := hex_to_number('8EB44A8768581511');
      l_h6 := hex_to_number('DB0C2E0D64F98FA7');
      l_h7 := hex_to_number('47B5481DBEFA4FA4');
    END IF;

    l_k_hex(0) := '428A2F98D728AE22'; l_k_hex(1) := '7137449123EF65CD';
    l_k_hex(2) := 'B5C0FBCFEC4D3B2F'; l_k_hex(3) := 'E9B5DBA58189DBBC';
    l_k_hex(4) := '3956C25BF348B538'; l_k_hex(5) := '59F111F1B605D019';
    l_k_hex(6) := '923F82A4AF194F9B'; l_k_hex(7) := 'AB1C5ED5DA6D8118';
    l_k_hex(8) := 'D807AA98A3030242'; l_k_hex(9) := '12835B0145706FBE';
    l_k_hex(10) := '243185BE4EE4B28C'; l_k_hex(11) := '550C7DC3D5FFB4E2';
    l_k_hex(12) := '72BE5D74F27B896F'; l_k_hex(13) := '80DEB1FE3B1696B1';
    l_k_hex(14) := '9BDC06A725C71235'; l_k_hex(15) := 'C19BF174CF692694';
    l_k_hex(16) := 'E49B69C19EF14AD2'; l_k_hex(17) := 'EFBE4786384F25E3';
    l_k_hex(18) := '0FC19DC68B8CD5B5'; l_k_hex(19) := '240CA1CC77AC9C65';
    l_k_hex(20) := '2DE92C6F592B0275'; l_k_hex(21) := '4A7484AA6EA6E483';
    l_k_hex(22) := '5CB0A9DCBD41FBD4'; l_k_hex(23) := '76F988DA831153B5';
    l_k_hex(24) := '983E5152EE66DFAB'; l_k_hex(25) := 'A831C66D2DB43210';
    l_k_hex(26) := 'B00327C898FB213F'; l_k_hex(27) := 'BF597FC7BEEF0EE4';
    l_k_hex(28) := 'C6E00BF33DA88FC2'; l_k_hex(29) := 'D5A79147930AA725';
    l_k_hex(30) := '06CA6351E003826F'; l_k_hex(31) := '142929670A0E6E70';
    l_k_hex(32) := '27B70A8546D22FFC'; l_k_hex(33) := '2E1B21385C26C926';
    l_k_hex(34) := '4D2C6DFC5AC42AED'; l_k_hex(35) := '53380D139D95B3DF';
    l_k_hex(36) := '650A73548BAF63DE'; l_k_hex(37) := '766A0ABB3C77B2A8';
    l_k_hex(38) := '81C2C92E47EDAEE6'; l_k_hex(39) := '92722C851482353B';
    l_k_hex(40) := 'A2BFE8A14CF10364'; l_k_hex(41) := 'A81A664BBC423001';
    l_k_hex(42) := 'C24B8B70D0F89791'; l_k_hex(43) := 'C76C51A30654BE30';
    l_k_hex(44) := 'D192E819D6EF5218'; l_k_hex(45) := 'D69906245565A910';
    l_k_hex(46) := 'F40E35855771202A'; l_k_hex(47) := '106AA07032BBD1B8';
    l_k_hex(48) := '19A4C116B8D2D0C8'; l_k_hex(49) := '1E376C085141AB53';
    l_k_hex(50) := '2748774CDF8EEB99'; l_k_hex(51) := '34B0BCB5E19B48A8';
    l_k_hex(52) := '391C0CB3C5C95A63'; l_k_hex(53) := '4ED8AA4AE3418ACB';
    l_k_hex(54) := '5B9CCA4F7763E373'; l_k_hex(55) := '682E6FF3D6B2B8A3';
    l_k_hex(56) := '748F82EE5DEFB2FC'; l_k_hex(57) := '78A5636F43172F60';
    l_k_hex(58) := '84C87814A1F0AB72'; l_k_hex(59) := '8CC702081A6439EC';
    l_k_hex(60) := '90BEFFFA23631E28'; l_k_hex(61) := 'A4506CEBDE82BDE9';
    l_k_hex(62) := 'BEF9A3F7B2C67915'; l_k_hex(63) := 'C67178F2E372532B';
    l_k_hex(64) := 'CA273ECEEA26619C'; l_k_hex(65) := 'D186B8C721C0C207';
    l_k_hex(66) := 'EADA7DD6CDE0EB1E'; l_k_hex(67) := 'F57D4F7FEE6ED178';
    l_k_hex(68) := '06F067AA72176FBA'; l_k_hex(69) := '0A637DC5A2C898A6';
    l_k_hex(70) := '113F9804BEF90DAE'; l_k_hex(71) := '1B710B35131C471B';
    l_k_hex(72) := '28DB77F523047D84'; l_k_hex(73) := '32CAAB7B40C72493';
    l_k_hex(74) := '3C9EBE0A15C9BEBC'; l_k_hex(75) := '431D67C49C100D4C';
    l_k_hex(76) := '4CC5D4BECB3E42B6'; l_k_hex(77) := '597F299CFC657E2A';
    l_k_hex(78) := '5FCB6FAB3AD6FAEC'; l_k_hex(79) := '6C44198C4A475817';
    FOR j IN 0 .. 79 LOOP
      l_k(j) := hex_to_number(l_k_hex(j));
    END LOOP;

    IF p_data IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_data);
      WHILE l_offset + 127 <= l_length LOOP
        l_block := DBMS_LOB.SUBSTR(p_data, 128, l_offset);
        process_block(l_block);
        l_offset := l_offset + 128;
      END LOOP;
      l_tail := DBMS_LOB.SUBSTR(p_data, 128, l_offset);
    END IF;

    l_tail_length := NVL(UTL_RAW.LENGTH(l_tail), 0);
    IF l_tail_length = 0 THEN
      l_tail := HEXTORAW('80');
    ELSE
      l_tail := UTL_RAW.CONCAT(l_tail, HEXTORAW('80'));
    END IF;
    IF l_tail_length + 1 > 112 THEN
      l_padding_length := 128 - UTL_RAW.LENGTH(l_tail);
      IF l_padding_length > 0 THEN
        l_tail := UTL_RAW.CONCAT(l_tail, HEXTORAW(RPAD('0', l_padding_length * 2, '0')));
      END IF;
      process_block(l_tail);
      l_tail := HEXTORAW(RPAD('0', 224, '0'));
    END IF;
    l_padding_length := 112 - UTL_RAW.LENGTH(l_tail);
    IF l_padding_length > 0 THEN
      l_tail := UTL_RAW.CONCAT(l_tail, HEXTORAW(RPAD('0', l_padding_length * 2, '0')));
    END IF;
    FOR j IN REVERSE 0 .. 7 LOOP
      l_tail := UTL_RAW.CONCAT(l_tail, HEXTORAW('00'));
    END LOOP;
    FOR j IN REVERSE 0 .. 7 LOOP
      l_tail := UTL_RAW.CONCAT(
        l_tail,
        HEXTORAW(byte_hex(MOD(TRUNC(l_length * 8 / POWER(256, j)), 256)))
      );
    END LOOP;
    process_block(l_tail);

    l_hex := word_hex(l_h0) || word_hex(l_h1) || word_hex(l_h2) ||
             word_hex(l_h3) || word_hex(l_h4) || word_hex(l_h5);
    IF p_sha512 THEN
      l_hex := l_hex || word_hex(l_h6) || word_hex(l_h7);
    END IF;
    RETURN LOWER(l_hex);
  END hash_blob_sha384_internal;

  FUNCTION crc32_blob_internal(p_data BLOB) RETURN VARCHAR2 IS
    c_hex CONSTANT VARCHAR2(16) := '0123456789ABCDEF';
    c_poly CONSTANT NUMBER := 3988292384; -- 0xEDB88320, CRC-32/ISO-HDLC
    l_crc NUMBER := 4294967295;
    l_length NUMBER := 0;
    l_offset NUMBER := 1;
    l_byte_raw RAW(1);
    l_byte_hex VARCHAR2(2);
    l_byte NUMBER;
    l_hex VARCHAR2(8);
  BEGIN
    IF p_data IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_data);
      WHILE l_offset <= l_length LOOP
        l_byte_raw := DBMS_LOB.SUBSTR(p_data, 1, l_offset);
        l_byte_hex := RAWTOHEX(l_byte_raw);
        l_byte := (INSTR(c_hex, SUBSTR(l_byte_hex, 1, 1)) - 1) * 16
                + INSTR(c_hex, SUBSTR(l_byte_hex, 2, 1)) - 1;
        l_crc := bit_xor32(l_crc, l_byte);

        FOR i IN 1 .. 8 LOOP
          IF MOD(l_crc, 2) = 1 THEN
            l_crc := bit_xor32(TRUNC(l_crc / 2), c_poly);
          ELSE
            l_crc := TRUNC(l_crc / 2);
          END IF;
        END LOOP;
        l_offset := l_offset + 1;
      END LOOP;
    END IF;

    l_crc := bit_xor32(l_crc, 4294967295);
    FOR i IN REVERSE 1 .. 8 LOOP
      l_hex := SUBSTR(c_hex, MOD(l_crc, 16) + 1, 1) || l_hex;
      l_crc := TRUNC(l_crc / 16);
    END LOOP;
    RETURN LOWER(l_hex);
  END crc32_blob_internal;

  /**
   * @brief Calcula MD5 dos bytes UTF-8 de VARCHAR2.
    * @param p_texto Texto de entrada.
   * @return Digest hexadecimal minúsculo de 32 caracteres.
   */
  FUNCTION hash_md5(p_texto IN VARCHAR2) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_raw RAW(32767);
    l_result VARCHAR2(32);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    l_raw := UTL_I18N.STRING_TO_RAW(p_texto, 'AL32UTF8');
    IF l_raw IS NOT NULL THEN
      DBMS_LOB.WRITEAPPEND(l_blob, UTL_RAW.LENGTH(l_raw), l_raw);
    END IF;
    l_result := hash_blob_internal(l_blob);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_blob);
      END IF;
      RAISE;
  END hash_md5;

  /**
   * @brief Calcula MD5 do CLOB codificado como UTF-8.
   * @param p_texto Conteúdo textual.
   * @return Digest hexadecimal minúsculo de 32 caracteres.
   */
  FUNCTION hash_md5(p_texto IN CLOB) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_text VARCHAR2(8000);
    l_raw RAW(32767);
    l_offset NUMBER := 1;
    l_length NUMBER := 0;
    l_result VARCHAR2(32);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    IF p_texto IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_texto);
    END IF;
    WHILE l_offset <= l_length LOOP
      l_text := DBMS_LOB.SUBSTR(p_texto, 8000, l_offset);
      l_raw := UTL_I18N.STRING_TO_RAW(l_text, 'AL32UTF8');
      IF l_raw IS NOT NULL THEN
        DBMS_LOB.WRITEAPPEND(l_blob, UTL_RAW.LENGTH(l_raw), l_raw);
      END IF;
      l_offset := l_offset + LENGTH(l_text);
    END LOOP;
    l_result := hash_blob_internal(l_blob);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_blob);
      END IF;
      RAISE;
  END hash_md5;

  /**
   * @brief Calcula MD5 dos bytes do BLOB.
   * @param p_texto Conteúdo binário.
   * @return Digest hexadecimal minúsculo de 32 caracteres.
   */
  FUNCTION hash_md5(p_texto IN BLOB) RETURN VARCHAR2 IS
  BEGIN
    RETURN hash_blob_internal(p_texto);
  END hash_md5;

  /**
   * @brief Calcula MD5 da representação decimal TM9 do número.
   * @param p_numero Valor numérico.
   * @return Digest hexadecimal minúsculo de 32 caracteres.
   */
  FUNCTION hash_md5(p_numero IN NUMBER) RETURN VARCHAR2 IS
  BEGIN
    RETURN hash_md5(TO_CHAR(p_numero, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,'''));
  END hash_md5;

  /**
   * @brief Calcula SHA-1 dos bytes UTF-8 de VARCHAR2.
   * @param p_texto Texto de entrada.
   * @return Digest hexadecimal minúsculo de 40 caracteres.
   */
  FUNCTION hash_sha1(p_texto IN VARCHAR2) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_raw RAW(32767);
    l_result VARCHAR2(40);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    l_raw := UTL_I18N.STRING_TO_RAW(p_texto, 'AL32UTF8');
    IF l_raw IS NOT NULL THEN
      DBMS_LOB.WRITEAPPEND(l_blob, UTL_RAW.LENGTH(l_raw), l_raw);
    END IF;
    l_result := hash_blob_sha1_internal(l_blob);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_blob);
      END IF;
      RAISE;
  END hash_sha1;

  /**
   * @brief Calcula SHA-1 do CLOB codificado como UTF-8.
   * @param p_texto Conteúdo textual.
   * @return Digest hexadecimal minúsculo de 40 caracteres.
   */
  FUNCTION hash_sha1(p_texto IN CLOB) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_text VARCHAR2(8000);
    l_raw RAW(32767);
    l_offset NUMBER := 1;
    l_length NUMBER := 0;
    l_result VARCHAR2(40);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    IF p_texto IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_texto);
    END IF;
    WHILE l_offset <= l_length LOOP
      l_text := DBMS_LOB.SUBSTR(p_texto, 8000, l_offset);
      l_raw := UTL_I18N.STRING_TO_RAW(l_text, 'AL32UTF8');
      IF l_raw IS NOT NULL THEN
        DBMS_LOB.WRITEAPPEND(l_blob, UTL_RAW.LENGTH(l_raw), l_raw);
      END IF;
      l_offset := l_offset + LENGTH(l_text);
    END LOOP;
    l_result := hash_blob_sha1_internal(l_blob);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_blob);
      END IF;
      RAISE;
  END hash_sha1;

  /**
   * @brief Calcula SHA-1 dos bytes do BLOB.
   * @param p_texto Conteúdo binário.
   * @return Digest hexadecimal minúsculo de 40 caracteres.
   */
  FUNCTION hash_sha1(p_texto IN BLOB) RETURN VARCHAR2 IS
  BEGIN
    RETURN hash_blob_sha1_internal(p_texto);
  END hash_sha1;

  /**
   * @brief Calcula SHA-1 da representação decimal TM9 do número.
   * @param p_numero Valor numérico.
   * @return Digest hexadecimal minúsculo de 40 caracteres.
   */
  FUNCTION hash_sha1(p_numero IN NUMBER) RETURN VARCHAR2 IS
  BEGIN
    RETURN hash_sha1(TO_CHAR(p_numero, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,'''));
  END hash_sha1;

  /**
   * @brief Calcula SHA-256 dos bytes UTF-8 de VARCHAR2.
   * @param p_texto Texto de entrada.
   * @return Digest hexadecimal minúsculo de 64 caracteres.
   */
  FUNCTION hash_sha256(p_texto IN VARCHAR2) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_raw RAW(32767);
    l_result VARCHAR2(64);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    l_raw := UTL_I18N.STRING_TO_RAW(p_texto, 'AL32UTF8');
    IF l_raw IS NOT NULL THEN
      DBMS_LOB.WRITEAPPEND(l_blob, UTL_RAW.LENGTH(l_raw), l_raw);
    END IF;
    l_result := hash_blob_sha256_internal(l_blob);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_blob);
      END IF;
      RAISE;
  END hash_sha256;

  /**
   * @brief Calcula SHA-256 do CLOB codificado como UTF-8.
   * @param p_texto Conteúdo textual.
   * @return Digest hexadecimal minúsculo de 64 caracteres.
   */
  FUNCTION hash_sha256(p_texto IN CLOB) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_text VARCHAR2(8000);
    l_raw RAW(32767);
    l_offset NUMBER := 1;
    l_length NUMBER := 0;
    l_result VARCHAR2(64);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    IF p_texto IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_texto);
    END IF;
    WHILE l_offset <= l_length LOOP
      l_text := DBMS_LOB.SUBSTR(p_texto, 8000, l_offset);
      l_raw := UTL_I18N.STRING_TO_RAW(l_text, 'AL32UTF8');
      IF l_raw IS NOT NULL THEN
        DBMS_LOB.WRITEAPPEND(l_blob, UTL_RAW.LENGTH(l_raw), l_raw);
      END IF;
      l_offset := l_offset + LENGTH(l_text);
    END LOOP;
    l_result := hash_blob_sha256_internal(l_blob);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_blob);
      END IF;
      RAISE;
  END hash_sha256;

  /**
   * @brief Calcula SHA-256 dos bytes do BLOB.
   * @param p_texto Conteúdo binário.
   * @return Digest hexadecimal minúsculo de 64 caracteres.
   */
  FUNCTION hash_sha256(p_texto IN BLOB) RETURN VARCHAR2 IS
  BEGIN
    RETURN hash_blob_sha256_internal(p_texto);
  END hash_sha256;

  /**
   * @brief Calcula SHA-256 da representação decimal TM9 do número.
   * @param p_numero Valor numérico.
   * @return Digest hexadecimal minúsculo de 64 caracteres.
   */
  FUNCTION hash_sha256(p_numero IN NUMBER) RETURN VARCHAR2 IS
  BEGIN
    RETURN hash_sha256(TO_CHAR(p_numero, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,'''));
  END hash_sha256;

  /**
   * @brief Calcula SHA3-224 dos bytes UTF-8 de VARCHAR2.
   * @param p_texto Texto de entrada.
   * @return Digest hexadecimal minúsculo de 56 caracteres.
   */
  FUNCTION hash_sha3_224(p_texto IN VARCHAR2) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_result VARCHAR2(56);
  BEGIN
    l_blob := aes_string_blob(p_texto);
    l_result := hash_blob_sha3_internal(l_blob, 28);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN DBMS_LOB.FREETEMPORARY(l_blob); END IF;
      RAISE;
  END hash_sha3_224;

  /**
   * @brief Calcula SHA3-224 do CLOB convertido para UTF-8.
   * @param p_texto CLOB de entrada.
   * @return Digest hexadecimal minúsculo de 56 caracteres.
   */
  FUNCTION hash_sha3_224(p_texto IN CLOB) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_text VARCHAR2(8000);
    l_raw RAW(32767);
    l_offset NUMBER := 1;
    l_length NUMBER := 0;
    l_result VARCHAR2(56);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    IF p_texto IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_texto);
    END IF;
    WHILE l_offset <= l_length LOOP
      l_text := DBMS_LOB.SUBSTR(p_texto, 8000, l_offset);
      l_raw := UTL_I18N.STRING_TO_RAW(l_text, 'AL32UTF8');
      IF l_raw IS NOT NULL THEN
        DBMS_LOB.WRITEAPPEND(l_blob, UTL_RAW.LENGTH(l_raw), l_raw);
      END IF;
      l_offset := l_offset + LENGTH(l_text);
    END LOOP;
    l_result := hash_blob_sha3_internal(l_blob, 28);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN DBMS_LOB.FREETEMPORARY(l_blob); END IF;
      RAISE;
  END hash_sha3_224;

  /**
   * @brief Calcula SHA3-224 dos bytes do BLOB.
   * @param p_texto Conteúdo binário.
   * @return Digest hexadecimal minúsculo de 56 caracteres.
   */
  FUNCTION hash_sha3_224(p_texto IN BLOB) RETURN VARCHAR2 IS
  BEGIN
    RETURN hash_blob_sha3_internal(p_texto, 28);
  END hash_sha3_224;

  /**
   * @brief Calcula SHA3-224 da representação decimal TM9 de NUMBER.
   * @param p_numero Valor numérico.
   * @return Digest hexadecimal minúsculo de 56 caracteres.
   */
  FUNCTION hash_sha3_224(p_numero IN NUMBER) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_text VARCHAR2(128);
    l_result VARCHAR2(56);
  BEGIN
    l_text := TO_CHAR(p_numero, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,''');
    l_blob := aes_string_blob(l_text);
    l_result := hash_blob_sha3_internal(l_blob, 28);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN DBMS_LOB.FREETEMPORARY(l_blob); END IF;
      RAISE;
  END hash_sha3_224;

  /**
   * @brief Calcula SHA3-256 dos bytes UTF-8 de VARCHAR2.
   * @param p_texto Texto de entrada.
   * @return Digest hexadecimal minúsculo de 64 caracteres.
   */
  FUNCTION hash_sha3_256(p_texto IN VARCHAR2) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_result VARCHAR2(64);
  BEGIN
    l_blob := aes_string_blob(p_texto);
    l_result := hash_blob_sha3_internal(l_blob, 32);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN DBMS_LOB.FREETEMPORARY(l_blob); END IF;
      RAISE;
  END hash_sha3_256;

  /**
   * @brief Calcula SHA3-256 do CLOB codificado como UTF-8.
   * @param p_texto Conteúdo textual.
   * @return Digest hexadecimal minúsculo de 64 caracteres.
   */
  FUNCTION hash_sha3_256(p_texto IN CLOB) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_text VARCHAR2(8000);
    l_raw RAW(32767);
    l_offset NUMBER := 1;
    l_length NUMBER := 0;
    l_result VARCHAR2(64);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    IF p_texto IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_texto);
    END IF;
    WHILE l_offset <= l_length LOOP
      l_text := DBMS_LOB.SUBSTR(p_texto, 8000, l_offset);
      l_raw := UTL_I18N.STRING_TO_RAW(l_text, 'AL32UTF8');
      IF l_raw IS NOT NULL THEN
        DBMS_LOB.WRITEAPPEND(l_blob, UTL_RAW.LENGTH(l_raw), l_raw);
      END IF;
      l_offset := l_offset + LENGTH(l_text);
    END LOOP;
    l_result := hash_blob_sha3_internal(l_blob, 32);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN DBMS_LOB.FREETEMPORARY(l_blob); END IF;
      RAISE;
  END hash_sha3_256;

  /**
   * @brief Calcula SHA3-256 dos bytes do BLOB.
   * @param p_texto Conteúdo binário.
   * @return Digest hexadecimal minúsculo de 64 caracteres.
   */
  FUNCTION hash_sha3_256(p_texto IN BLOB) RETURN VARCHAR2 IS
  BEGIN
    RETURN hash_blob_sha3_internal(p_texto, 32);
  END hash_sha3_256;

  /**
   * @brief Calcula SHA3-256 da representação decimal TM9 do número.
   * @param p_numero Valor numérico.
   * @return Digest hexadecimal minúsculo de 64 caracteres.
   */
  FUNCTION hash_sha3_256(p_numero IN NUMBER) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_text VARCHAR2(128);
    l_result VARCHAR2(64);
  BEGIN
    l_text := TO_CHAR(p_numero, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,''');
    l_blob := aes_string_blob(l_text);
    l_result := hash_blob_sha3_internal(l_blob, 32);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN DBMS_LOB.FREETEMPORARY(l_blob); END IF;
      RAISE;
  END hash_sha3_256;

  /**
   * @brief Calcula SHA3-384 dos bytes UTF-8 de VARCHAR2.
   * @param p_texto Texto de entrada.
   * @return Digest hexadecimal minúsculo de 96 caracteres.
   */
  FUNCTION hash_sha3_384(p_texto IN VARCHAR2) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_result VARCHAR2(96);
  BEGIN
    l_blob := aes_string_blob(p_texto);
    l_result := hash_blob_sha3_internal(l_blob, 48);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN DBMS_LOB.FREETEMPORARY(l_blob); END IF;
      RAISE;
  END hash_sha3_384;

  /**
   * @brief Calcula SHA3-384 do CLOB convertido para UTF-8.
   * @param p_texto CLOB de entrada.
   * @return Digest hexadecimal minúsculo de 96 caracteres.
   */
  FUNCTION hash_sha3_384(p_texto IN CLOB) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_text VARCHAR2(8000);
    l_raw RAW(32767);
    l_offset NUMBER := 1;
    l_length NUMBER := 0;
    l_result VARCHAR2(96);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    IF p_texto IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_texto);
    END IF;
    WHILE l_offset <= l_length LOOP
      l_text := DBMS_LOB.SUBSTR(p_texto, 8000, l_offset);
      l_raw := UTL_I18N.STRING_TO_RAW(l_text, 'AL32UTF8');
      IF l_raw IS NOT NULL THEN
        DBMS_LOB.WRITEAPPEND(l_blob, UTL_RAW.LENGTH(l_raw), l_raw);
      END IF;
      l_offset := l_offset + LENGTH(l_text);
    END LOOP;
    l_result := hash_blob_sha3_internal(l_blob, 48);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN DBMS_LOB.FREETEMPORARY(l_blob); END IF;
      RAISE;
  END hash_sha3_384;

  /**
   * @brief Calcula SHA3-384 dos bytes do BLOB.
   * @param p_texto Conteúdo binário.
   * @return Digest hexadecimal minúsculo de 96 caracteres.
   */
  FUNCTION hash_sha3_384(p_texto IN BLOB) RETURN VARCHAR2 IS
  BEGIN
    RETURN hash_blob_sha3_internal(p_texto, 48);
  END hash_sha3_384;

  /**
   * @brief Calcula SHA3-384 da representação decimal TM9 de NUMBER.
   * @param p_numero Valor numérico.
   * @return Digest hexadecimal minúsculo de 96 caracteres.
   */
  FUNCTION hash_sha3_384(p_numero IN NUMBER) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_text VARCHAR2(128);
    l_result VARCHAR2(96);
  BEGIN
    l_text := TO_CHAR(p_numero, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,''');
    l_blob := aes_string_blob(l_text);
    l_result := hash_blob_sha3_internal(l_blob, 48);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN DBMS_LOB.FREETEMPORARY(l_blob); END IF;
      RAISE;
  END hash_sha3_384;

  /**
   * @brief Calcula SHA3-512 dos bytes UTF-8 de VARCHAR2.
   * @param p_texto Texto de entrada.
   * @return Digest hexadecimal minúsculo de 128 caracteres.
   */
  FUNCTION hash_sha3_512(p_texto IN VARCHAR2) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_result VARCHAR2(128);
  BEGIN
    l_blob := aes_string_blob(p_texto);
    l_result := hash_blob_sha3_internal(l_blob, 64);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN DBMS_LOB.FREETEMPORARY(l_blob); END IF;
      RAISE;
  END hash_sha3_512;

  /**
   * @brief Calcula SHA3-512 do CLOB convertido para UTF-8.
   * @param p_texto CLOB de entrada.
   * @return Digest hexadecimal minúsculo de 128 caracteres.
   */
  FUNCTION hash_sha3_512(p_texto IN CLOB) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_text VARCHAR2(8000);
    l_raw RAW(32767);
    l_offset NUMBER := 1;
    l_length NUMBER := 0;
    l_result VARCHAR2(128);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    IF p_texto IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_texto);
    END IF;
    WHILE l_offset <= l_length LOOP
      l_text := DBMS_LOB.SUBSTR(p_texto, 8000, l_offset);
      l_raw := UTL_I18N.STRING_TO_RAW(l_text, 'AL32UTF8');
      IF l_raw IS NOT NULL THEN
        DBMS_LOB.WRITEAPPEND(l_blob, UTL_RAW.LENGTH(l_raw), l_raw);
      END IF;
      l_offset := l_offset + LENGTH(l_text);
    END LOOP;
    l_result := hash_blob_sha3_internal(l_blob, 64);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN DBMS_LOB.FREETEMPORARY(l_blob); END IF;
      RAISE;
  END hash_sha3_512;

  /**
   * @brief Calcula SHA3-512 dos bytes do BLOB.
   * @param p_texto Conteúdo binário.
   * @return Digest hexadecimal minúsculo de 128 caracteres.
   */
  FUNCTION hash_sha3_512(p_texto IN BLOB) RETURN VARCHAR2 IS
  BEGIN
    RETURN hash_blob_sha3_internal(p_texto, 64);
  END hash_sha3_512;

  /**
   * @brief Calcula SHA3-512 da representação decimal TM9 de NUMBER.
   * @param p_numero Valor numérico.
   * @return Digest hexadecimal minúsculo de 128 caracteres.
   */
  FUNCTION hash_sha3_512(p_numero IN NUMBER) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_text VARCHAR2(128);
    l_result VARCHAR2(128);
  BEGIN
    l_text := TO_CHAR(p_numero, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,''');
    l_blob := aes_string_blob(l_text);
    l_result := hash_blob_sha3_internal(l_blob, 64);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN DBMS_LOB.FREETEMPORARY(l_blob); END IF;
      RAISE;
  END hash_sha3_512;

  /**
   * @brief Calcula SHA-384 dos bytes UTF-8 de VARCHAR2.
   * @param p_texto Texto de entrada.
   * @return Digest hexadecimal minúsculo de 96 caracteres.
   */
  FUNCTION hash_sha384(p_texto IN VARCHAR2) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_raw RAW(32767);
    l_result VARCHAR2(96);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    l_raw := UTL_I18N.STRING_TO_RAW(p_texto, 'AL32UTF8');
    IF l_raw IS NOT NULL THEN
      DBMS_LOB.WRITEAPPEND(l_blob, UTL_RAW.LENGTH(l_raw), l_raw);
    END IF;
    l_result := hash_blob_sha384_internal(l_blob);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_blob);
      END IF;
      RAISE;
  END hash_sha384;

  /**
   * @brief Calcula SHA-384 do CLOB codificado como UTF-8.
   * @param p_texto Conteúdo textual.
   * @return Digest hexadecimal minúsculo de 96 caracteres.
   */
  FUNCTION hash_sha384(p_texto IN CLOB) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_text VARCHAR2(8000);
    l_raw RAW(32767);
    l_offset NUMBER := 1;
    l_length NUMBER := 0;
    l_result VARCHAR2(96);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    IF p_texto IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_texto);
    END IF;
    WHILE l_offset <= l_length LOOP
      l_text := DBMS_LOB.SUBSTR(p_texto, 8000, l_offset);
      l_raw := UTL_I18N.STRING_TO_RAW(l_text, 'AL32UTF8');
      IF l_raw IS NOT NULL THEN
        DBMS_LOB.WRITEAPPEND(l_blob, UTL_RAW.LENGTH(l_raw), l_raw);
      END IF;
      l_offset := l_offset + LENGTH(l_text);
    END LOOP;
    l_result := hash_blob_sha384_internal(l_blob);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_blob);
      END IF;
      RAISE;
  END hash_sha384;

  /**
   * @brief Calcula SHA-384 dos bytes do BLOB.
   * @param p_texto Conteúdo binário.
   * @return Digest hexadecimal minúsculo de 96 caracteres.
   */
  FUNCTION hash_sha384(p_texto IN BLOB) RETURN VARCHAR2 IS
  BEGIN
    RETURN hash_blob_sha384_internal(p_texto);
  END hash_sha384;

  /**
   * @brief Calcula SHA-384 da representação decimal TM9 do número.
   * @param p_numero Valor numérico.
   * @return Digest hexadecimal minúsculo de 96 caracteres.
   */
  FUNCTION hash_sha384(p_numero IN NUMBER) RETURN VARCHAR2 IS
  BEGIN
    RETURN hash_sha384(TO_CHAR(p_numero, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,'''));
  END hash_sha384;

  /**
   * @brief Calcula SHA-512 dos bytes UTF-8 de VARCHAR2.
   * @param p_texto Texto de entrada.
   * @return Digest hexadecimal minúsculo de 128 caracteres.
   */
  FUNCTION hash_sha512(p_texto IN VARCHAR2) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_raw RAW(32767);
    l_result VARCHAR2(128);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    l_raw := UTL_I18N.STRING_TO_RAW(p_texto, 'AL32UTF8');
    IF l_raw IS NOT NULL THEN
      DBMS_LOB.WRITEAPPEND(l_blob, UTL_RAW.LENGTH(l_raw), l_raw);
    END IF;
    l_result := hash_blob_sha384_internal(l_blob, TRUE);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_blob);
      END IF;
      RAISE;
  END hash_sha512;

  /**
   * @brief Calcula SHA-512 do CLOB codificado como UTF-8.
   * @param p_texto Conteúdo textual.
   * @return Digest hexadecimal minúsculo de 128 caracteres.
   */
  FUNCTION hash_sha512(p_texto IN CLOB) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_text VARCHAR2(8000);
    l_raw RAW(32767);
    l_offset NUMBER := 1;
    l_length NUMBER := 0;
    l_result VARCHAR2(128);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    IF p_texto IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_texto);
    END IF;
    WHILE l_offset <= l_length LOOP
      l_text := DBMS_LOB.SUBSTR(p_texto, 8000, l_offset);
      l_raw := UTL_I18N.STRING_TO_RAW(l_text, 'AL32UTF8');
      IF l_raw IS NOT NULL THEN
        DBMS_LOB.WRITEAPPEND(l_blob, UTL_RAW.LENGTH(l_raw), l_raw);
      END IF;
      l_offset := l_offset + LENGTH(l_text);
    END LOOP;
    l_result := hash_blob_sha384_internal(l_blob, TRUE);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_blob);
      END IF;
      RAISE;
  END hash_sha512;

  /**
   * @brief Calcula SHA-512 dos bytes do BLOB.
   * @param p_texto Conteúdo binário.
   * @return Digest hexadecimal minúsculo de 128 caracteres.
   */
  FUNCTION hash_sha512(p_texto IN BLOB) RETURN VARCHAR2 IS
  BEGIN
    RETURN hash_blob_sha384_internal(p_texto, TRUE);
  END hash_sha512;

  /**
   * @brief Calcula SHA-512 da representação decimal TM9 do número.
   * @param p_numero Valor numérico.
   * @return Digest hexadecimal minúsculo de 128 caracteres.
   */
  FUNCTION hash_sha512(p_numero IN NUMBER) RETURN VARCHAR2 IS
  BEGIN
    RETURN hash_sha512(TO_CHAR(p_numero, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,'''));
  END hash_sha512;

  /**
   * @brief Calcula CRC-32/ISO-HDLC dos bytes UTF-8 de VARCHAR2.
   * @param p_texto Texto de entrada.
   * @return CRC hexadecimal minúsculo de 8 caracteres.
   */
  FUNCTION hash_crc32(p_texto IN VARCHAR2) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_raw RAW(32767);
    l_result VARCHAR2(8);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    l_raw := UTL_I18N.STRING_TO_RAW(p_texto, 'AL32UTF8');
    IF l_raw IS NOT NULL THEN
      DBMS_LOB.WRITEAPPEND(l_blob, UTL_RAW.LENGTH(l_raw), l_raw);
    END IF;
    l_result := crc32_blob_internal(l_blob);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_blob);
      END IF;
      RAISE;
  END hash_crc32;

  /**
   * @brief Calcula CRC-32/ISO-HDLC do CLOB codificado como UTF-8.
   * @param p_texto Conteúdo textual.
   * @return CRC hexadecimal minúsculo de 8 caracteres.
   */
  FUNCTION hash_crc32(p_texto IN CLOB) RETURN VARCHAR2 IS
    l_blob BLOB;
    l_text VARCHAR2(8000);
    l_raw RAW(32767);
    l_offset NUMBER := 1;
    l_length NUMBER := 0;
    l_result VARCHAR2(8);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_blob, TRUE);
    IF p_texto IS NOT NULL THEN
      l_length := DBMS_LOB.GETLENGTH(p_texto);
    END IF;
    WHILE l_offset <= l_length LOOP
      l_text := DBMS_LOB.SUBSTR(p_texto, 8000, l_offset);
      l_raw := UTL_I18N.STRING_TO_RAW(l_text, 'AL32UTF8');
      IF l_raw IS NOT NULL THEN
        DBMS_LOB.WRITEAPPEND(l_blob, UTL_RAW.LENGTH(l_raw), l_raw);
      END IF;
      l_offset := l_offset + LENGTH(l_text);
    END LOOP;
    l_result := crc32_blob_internal(l_blob);
    DBMS_LOB.FREETEMPORARY(l_blob);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_blob) = 1 THEN
        DBMS_LOB.FREETEMPORARY(l_blob);
      END IF;
      RAISE;
  END hash_crc32;

  /**
   * @brief Calcula CRC-32/ISO-HDLC dos bytes do BLOB.
   * @param p_texto Conteúdo binário.
   * @return CRC hexadecimal minúsculo de 8 caracteres.
   */
  FUNCTION hash_crc32(p_texto IN BLOB) RETURN VARCHAR2 IS
  BEGIN
    RETURN crc32_blob_internal(p_texto);
  END hash_crc32;

  /**
   * @brief Calcula CRC-32/ISO-HDLC da representação TM9 do número.
   * @param p_numero Valor numérico.
   * @return CRC hexadecimal minúsculo de 8 caracteres.
   */
  FUNCTION hash_crc32(p_numero IN NUMBER) RETURN VARCHAR2 IS
  BEGIN
    RETURN hash_crc32(TO_CHAR(p_numero, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,'''));
  END hash_crc32;

  /**
   * @brief Cifra texto UTF-8 usando AES-128-CBC/PKCS#7.
    * @param p_texto_varchar2 Texto de entrada.
   * @param p_chave Chave com 16 bytes UTF-8.
   * @param p_iv IV de 16 bytes, único e imprevisível.
   * @return Ciphertext hexadecimal em VARCHAR2.
   */
  FUNCTION cripto_aes128(p_texto_varchar2 IN VARCHAR2, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    RETURN aes_encrypt_text_hex(p_texto_varchar2, p_chave, p_iv, 16);
  END cripto_aes128;

  /**
   * @brief Cifra CLOB UTF-8 usando AES-128-CBC/PKCS#7.
    * @param p_texto_clob CLOB de entrada.
   * @param p_chave Chave com 16 bytes UTF-8.
   * @param p_iv IV de 16 bytes, único e imprevisível.
   * @return Ciphertext hexadecimal em CLOB.
   */
  FUNCTION cripto_aes128(p_texto_clob IN CLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN CLOB IS
    l_plain BLOB;
    l_cipher BLOB;
    l_result CLOB;
    l_key RAW(16) := aes_key_raw(p_chave, 'Chave AES');
    l_iv RAW(16) := aes_key_raw(p_iv, 'IV');
  BEGIN
    l_plain := aes_clob_to_blob(p_texto_clob);
    l_cipher := aes_encrypt_blob(l_plain, l_key, l_iv);
    l_result := aes_hex_blob(l_cipher);
    DBMS_LOB.FREETEMPORARY(l_plain);
    DBMS_LOB.FREETEMPORARY(l_cipher);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_plain) = 1 THEN DBMS_LOB.FREETEMPORARY(l_plain); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_cipher) = 1 THEN DBMS_LOB.FREETEMPORARY(l_cipher); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_result) = 1 THEN DBMS_LOB.FREETEMPORARY(l_result); END IF;
      RAISE;
  END cripto_aes128;

  /**
   * @brief Cifra bytes BLOB usando AES-128-CBC/PKCS#7.
    * @param p_texto_blob BLOB de entrada.
   * @param p_chave Chave com 16 bytes UTF-8.
   * @param p_iv IV de 16 bytes, único e imprevisível.
   * @return Ciphertext binário em BLOB.
   */
  FUNCTION cripto_aes128(p_texto_blob IN BLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN BLOB IS
  BEGIN
    RETURN aes_encrypt_blob(
      p_texto_blob,
      aes_key_raw(p_chave, 'Chave AES'),
      aes_key_raw(p_iv, 'IV')
    );
  END cripto_aes128;

  /**
   * @brief Cifra representação TM9 do NUMBER com AES-128-CBC/PKCS#7.
   * @param p_numero Número de entrada.
   * @param p_chave Chave com 16 bytes UTF-8.
   * @param p_iv IV de 16 bytes, único e imprevisível.
   * @return Ciphertext hexadecimal em VARCHAR2.
   */
  FUNCTION cripto_aes128(p_numero IN NUMBER, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    RETURN aes_encrypt_text_hex(
      TO_CHAR(p_numero, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,'''),
      p_chave,
      p_iv,
      16
    );
  END cripto_aes128;

  /**
   * @brief Cifra bytes RAW usando AES-128-CBC/PKCS#7.
    * @param p_texto_raw Dados binários.
   * @param p_chave Chave com 16 bytes UTF-8.
   * @param p_iv IV de 16 bytes, único e imprevisível.
   * @return Ciphertext binário em RAW.
   */
  FUNCTION cripto_aes128(p_texto_raw IN RAW, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN RAW IS
    l_plain BLOB;
    l_cipher BLOB;
    l_length NUMBER;
    l_result RAW(32767);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_plain, TRUE);
    IF p_texto_raw IS NOT NULL THEN
      DBMS_LOB.WRITEAPPEND(l_plain, UTL_RAW.LENGTH(p_texto_raw), p_texto_raw);
    END IF;
    l_cipher := aes_encrypt_blob(
      l_plain,
      aes_key_raw(p_chave, 'Chave AES'),
      aes_key_raw(p_iv, 'IV')
    );
    l_length := DBMS_LOB.GETLENGTH(l_cipher);
    IF l_length > 32767 THEN
      RAISE_APPLICATION_ERROR(-20011, 'Ciphertext excede o limite de retorno RAW.');
    END IF;
    l_result := DBMS_LOB.SUBSTR(l_cipher, l_length, 1);
    DBMS_LOB.FREETEMPORARY(l_plain);
    DBMS_LOB.FREETEMPORARY(l_cipher);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_plain) = 1 THEN DBMS_LOB.FREETEMPORARY(l_plain); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_cipher) = 1 THEN DBMS_LOB.FREETEMPORARY(l_cipher); END IF;
      RAISE;
  END cripto_aes128;

  /**
   * @brief Decifra ciphertext hexadecimal AES-128-CBC/PKCS#7.
    * @param p_cifra_varchar2 Ciphertext hexadecimal.
   * @param p_chave Chave correspondente de 16 bytes UTF-8.
   * @param p_iv IV usado na cifra.
   * @param p_tipo VARCHAR2 ou NUMBER.
  * @return Texto recuperado; NUMBER valida a representação decimal e a retorna como texto.
   */
  FUNCTION descripto_aes128(p_cifra_varchar2 IN VARCHAR2, p_chave IN VARCHAR2, p_iv IN VARCHAR2, p_tipo IN VARCHAR2 DEFAULT 'VARCHAR2') RETURN VARCHAR2 IS
    l_hex CLOB;
    l_cipher BLOB;
    l_plain BLOB;
    l_text CLOB;
    l_result VARCHAR2(32767);
    l_key RAW(16) := aes_key_raw(p_chave, 'Chave AES');
    l_iv RAW(16) := aes_key_raw(p_iv, 'IV');
  BEGIN
    IF NVL(UPPER(p_tipo), '?') NOT IN ('VARCHAR2', 'NUMBER') THEN
      RAISE_APPLICATION_ERROR(-20012, 'p_tipo deve ser VARCHAR2 ou NUMBER.');
    END IF;
    DBMS_LOB.CREATETEMPORARY(l_hex, TRUE);
    IF p_cifra_varchar2 IS NOT NULL THEN
      DBMS_LOB.WRITEAPPEND(l_hex, LENGTH(p_cifra_varchar2), p_cifra_varchar2);
    END IF;
    l_cipher := aes_unhex_clob(l_hex);
    l_plain := aes_decrypt_blob(l_cipher, l_key, l_iv);
    l_text := aes_blob_to_clob(l_plain);
    IF DBMS_LOB.GETLENGTH(l_text) > 32767 THEN
      RAISE_APPLICATION_ERROR(-20015, 'Texto descriptografado excede o limite de VARCHAR2. Use a sobrecarga CLOB.');
    END IF;
    l_result := DBMS_LOB.SUBSTR(l_text, 32767, 1);
    IF UPPER(p_tipo) = 'NUMBER' THEN
      IF NOT REGEXP_LIKE(l_result, '^[+-]?([0-9]+([.][0-9]*)?|[.][0-9]+)([Ee][+-]?[0-9]+)?$') THEN
        RAISE_APPLICATION_ERROR(-20014, 'O conteúdo descriptografado não representa um NUMBER.');
      END IF;
    END IF;
    DBMS_LOB.FREETEMPORARY(l_hex);
    DBMS_LOB.FREETEMPORARY(l_cipher);
    DBMS_LOB.FREETEMPORARY(l_plain);
    DBMS_LOB.FREETEMPORARY(l_text);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_hex) = 1 THEN DBMS_LOB.FREETEMPORARY(l_hex); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_cipher) = 1 THEN DBMS_LOB.FREETEMPORARY(l_cipher); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_plain) = 1 THEN DBMS_LOB.FREETEMPORARY(l_plain); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_text) = 1 THEN DBMS_LOB.FREETEMPORARY(l_text); END IF;
      RAISE;
  END descripto_aes128;

  /**
   * @brief Decifra CLOB hexadecimal AES-128-CBC/PKCS#7.
    * @param p_cifra_clob Ciphertext hexadecimal.
   * @param p_chave Chave correspondente de 16 bytes UTF-8.
   * @param p_iv IV usado na cifra.
   * @param p_tipo VARCHAR2 ou NUMBER.
  * @return Texto recuperado em CLOB; NUMBER valida a representação decimal e a mantém como texto.
   */
  FUNCTION descripto_aes128(p_cifra_clob IN CLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2, p_tipo IN VARCHAR2 DEFAULT 'VARCHAR2') RETURN CLOB IS
    l_cipher BLOB;
    l_plain BLOB;
    l_result CLOB;
  BEGIN
    IF NVL(UPPER(p_tipo), '?') NOT IN ('VARCHAR2', 'NUMBER') THEN
      RAISE_APPLICATION_ERROR(-20012, 'p_tipo deve ser VARCHAR2 ou NUMBER.');
    END IF;
    l_cipher := aes_unhex_clob(p_cifra_clob);
    l_plain := aes_decrypt_blob(
      l_cipher,
      aes_key_raw(p_chave, 'Chave AES'),
      aes_key_raw(p_iv, 'IV')
    );
    l_result := aes_blob_to_clob(l_plain);
    IF UPPER(p_tipo) = 'NUMBER' THEN
      IF DBMS_LOB.GETLENGTH(l_result) > 128 OR
         NOT REGEXP_LIKE(DBMS_LOB.SUBSTR(l_result, 128, 1),
           '^[+-]?([0-9]+([.][0-9]*)?|[.][0-9]+)([Ee][+-]?[0-9]+)?$') THEN
        RAISE_APPLICATION_ERROR(-20014, 'O conteúdo descriptografado não representa um NUMBER.');
      END IF;
    END IF;
    DBMS_LOB.FREETEMPORARY(l_cipher);
    DBMS_LOB.FREETEMPORARY(l_plain);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_cipher) = 1 THEN DBMS_LOB.FREETEMPORARY(l_cipher); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_plain) = 1 THEN DBMS_LOB.FREETEMPORARY(l_plain); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_result) = 1 THEN DBMS_LOB.FREETEMPORARY(l_result); END IF;
      RAISE;
  END descripto_aes128;

  /**
   * @brief Decifra BLOB binário AES-128-CBC/PKCS#7.
    * @param p_cifra_blob Ciphertext binário.
   * @param p_chave Chave correspondente de 16 bytes UTF-8.
   * @param p_iv IV usado na cifra.
   * @return Dados recuperados em BLOB.
   */
  FUNCTION descripto_aes128(p_cifra_blob IN BLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN BLOB IS
  BEGIN
    RETURN aes_decrypt_blob(
      p_cifra_blob,
      aes_key_raw(p_chave, 'Chave AES'),
      aes_key_raw(p_iv, 'IV')
    );
  END descripto_aes128;

  /**
   * @brief Decifra RAW binário AES-128-CBC/PKCS#7.
    * @param p_cifra_raw Ciphertext binário.
   * @param p_chave Chave correspondente de 16 bytes UTF-8.
   * @param p_iv IV usado na cifra.
   * @return Dados recuperados em RAW.
   */
  FUNCTION descripto_aes128(p_cifra_raw IN RAW, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN RAW IS
    l_cipher BLOB;
    l_plain BLOB;
    l_length NUMBER;
    l_result RAW(32767);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_cipher, TRUE);
    IF p_cifra_raw IS NOT NULL THEN
      DBMS_LOB.WRITEAPPEND(l_cipher, UTL_RAW.LENGTH(p_cifra_raw), p_cifra_raw);
    END IF;
    l_plain := aes_decrypt_blob(
      l_cipher,
      aes_key_raw(p_chave, 'Chave AES'),
      aes_key_raw(p_iv, 'IV')
    );
    l_length := DBMS_LOB.GETLENGTH(l_plain);
    IF l_length > 32767 THEN
      RAISE_APPLICATION_ERROR(-20013, 'Texto descriptografado excede o limite de retorno RAW.');
    END IF;
    IF l_length > 0 THEN
      l_result := DBMS_LOB.SUBSTR(l_plain, l_length, 1);
    END IF;
    DBMS_LOB.FREETEMPORARY(l_cipher);
    DBMS_LOB.FREETEMPORARY(l_plain);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_cipher) = 1 THEN DBMS_LOB.FREETEMPORARY(l_cipher); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_plain) = 1 THEN DBMS_LOB.FREETEMPORARY(l_plain); END IF;
      RAISE;
  END descripto_aes128;

  /**
   * @brief Cifra texto UTF-8 usando AES-192-CBC/PKCS#7.
    * @param p_texto_varchar2 Texto de entrada.
   * @param p_chave Chave com 24 bytes UTF-8.
   * @param p_iv IV de 16 bytes, único e imprevisível.
   * @return Ciphertext hexadecimal em VARCHAR2.
   */
  FUNCTION cripto_aes192(p_texto_varchar2 IN VARCHAR2, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    RETURN aes_encrypt_text_hex(p_texto_varchar2, p_chave, p_iv, 24);
  END cripto_aes192;

  /**
   * @brief Cifra CLOB UTF-8 usando AES-192-CBC/PKCS#7.
    * @param p_texto_clob CLOB de entrada.
   * @param p_chave Chave com 24 bytes UTF-8.
   * @param p_iv IV de 16 bytes, único e imprevisível.
   * @return Ciphertext hexadecimal em CLOB.
   */
  FUNCTION cripto_aes192(p_texto_clob IN CLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN CLOB IS
    l_plain BLOB;
    l_cipher BLOB;
    l_result CLOB;
    l_key RAW(24) := aes_key_raw(p_chave, 'Chave AES-192', 24);
    l_iv RAW(16) := aes_key_raw(p_iv, 'IV');
  BEGIN
    l_plain := aes_clob_to_blob(p_texto_clob);
    l_cipher := aes_encrypt_blob(l_plain, l_key, l_iv, 24);
    l_result := aes_hex_blob(l_cipher);
    DBMS_LOB.FREETEMPORARY(l_plain);
    DBMS_LOB.FREETEMPORARY(l_cipher);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_plain) = 1 THEN DBMS_LOB.FREETEMPORARY(l_plain); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_cipher) = 1 THEN DBMS_LOB.FREETEMPORARY(l_cipher); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_result) = 1 THEN DBMS_LOB.FREETEMPORARY(l_result); END IF;
      RAISE;
  END cripto_aes192;

  /**
   * @brief Cifra bytes BLOB usando AES-192-CBC/PKCS#7.
    * @param p_texto_blob BLOB de entrada.
   * @param p_chave Chave com 24 bytes UTF-8.
   * @param p_iv IV de 16 bytes, único e imprevisível.
   * @return Ciphertext binário em BLOB.
   */
  FUNCTION cripto_aes192(p_texto_blob IN BLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN BLOB IS
  BEGIN
    RETURN aes_encrypt_blob(
      p_texto_blob,
      aes_key_raw(p_chave, 'Chave AES-192', 24),
      aes_key_raw(p_iv, 'IV'),
      24
    );
  END cripto_aes192;

  /**
   * @brief Cifra representação TM9 do NUMBER com AES-192-CBC/PKCS#7.
   * @param p_numero Número de entrada.
   * @param p_chave Chave com 24 bytes UTF-8.
   * @param p_iv IV de 16 bytes, único e imprevisível.
   * @return Ciphertext hexadecimal em VARCHAR2.
   */
  FUNCTION cripto_aes192(p_numero IN NUMBER, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    RETURN aes_encrypt_text_hex(
      TO_CHAR(p_numero, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,'''),
      p_chave,
      p_iv,
      24
    );
  END cripto_aes192;

  /**
   * @brief Cifra bytes RAW usando AES-192-CBC/PKCS#7.
    * @param p_texto_raw Dados binários.
   * @param p_chave Chave com 24 bytes UTF-8.
   * @param p_iv IV de 16 bytes, único e imprevisível.
   * @return Ciphertext binário em RAW.
   */
  FUNCTION cripto_aes192(p_texto_raw IN RAW, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN RAW IS
    l_plain BLOB;
    l_cipher BLOB;
    l_length NUMBER;
    l_result RAW(32767);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_plain, TRUE);
    IF p_texto_raw IS NOT NULL THEN
      DBMS_LOB.WRITEAPPEND(l_plain, UTL_RAW.LENGTH(p_texto_raw), p_texto_raw);
    END IF;
    l_cipher := aes_encrypt_blob(
      l_plain,
      aes_key_raw(p_chave, 'Chave AES-192', 24),
      aes_key_raw(p_iv, 'IV'),
      24
    );
    l_length := DBMS_LOB.GETLENGTH(l_cipher);
    IF l_length > 32767 THEN
      RAISE_APPLICATION_ERROR(-20011, 'Ciphertext excede o limite de retorno RAW.');
    END IF;
    l_result := DBMS_LOB.SUBSTR(l_cipher, l_length, 1);
    DBMS_LOB.FREETEMPORARY(l_plain);
    DBMS_LOB.FREETEMPORARY(l_cipher);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_plain) = 1 THEN DBMS_LOB.FREETEMPORARY(l_plain); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_cipher) = 1 THEN DBMS_LOB.FREETEMPORARY(l_cipher); END IF;
      RAISE;
  END cripto_aes192;

  /**
   * @brief Decifra ciphertext hexadecimal AES-192-CBC/PKCS#7.
    * @param p_cifra_varchar2 Ciphertext hexadecimal.
   * @param p_chave Chave correspondente de 24 bytes UTF-8.
   * @param p_iv IV usado na cifra.
   * @param p_tipo VARCHAR2 ou NUMBER.
  * @return Texto recuperado; NUMBER valida a representação decimal e a retorna como texto.
   */
  FUNCTION descripto_aes192(p_cifra_varchar2 IN VARCHAR2, p_chave IN VARCHAR2, p_iv IN VARCHAR2, p_tipo IN VARCHAR2 DEFAULT 'VARCHAR2') RETURN VARCHAR2 IS
    l_hex CLOB;
    l_cipher BLOB;
    l_plain BLOB;
    l_text CLOB;
    l_result VARCHAR2(32767);
  BEGIN
    IF NVL(UPPER(p_tipo), '?') NOT IN ('VARCHAR2', 'NUMBER') THEN
      RAISE_APPLICATION_ERROR(-20012, 'p_tipo deve ser VARCHAR2 ou NUMBER.');
    END IF;
    DBMS_LOB.CREATETEMPORARY(l_hex, TRUE);
    IF p_cifra_varchar2 IS NOT NULL THEN
      DBMS_LOB.WRITEAPPEND(l_hex, LENGTH(p_cifra_varchar2), p_cifra_varchar2);
    END IF;
    l_cipher := aes_unhex_clob(l_hex);
    l_plain := aes_decrypt_blob(l_cipher, aes_key_raw(p_chave, 'Chave AES-192', 24), aes_key_raw(p_iv, 'IV'), 24);
    l_text := aes_blob_to_clob(l_plain);
    IF DBMS_LOB.GETLENGTH(l_text) > 32767 THEN
      RAISE_APPLICATION_ERROR(-20015, 'Texto descriptografado excede o limite VARCHAR2; use a sobrecarga CLOB.');
    END IF;
    l_result := DBMS_LOB.SUBSTR(l_text, 32767, 1);
    IF UPPER(p_tipo) = 'NUMBER' THEN
      IF NOT REGEXP_LIKE(l_result, '^[+-]?([0-9]+([.][0-9]*)?|[.][0-9]+)([Ee][+-]?[0-9]+)?$') THEN
        RAISE_APPLICATION_ERROR(-20014, 'O conteúdo descriptografado não representa um NUMBER.');
      END IF;
    END IF;
    DBMS_LOB.FREETEMPORARY(l_hex);
    DBMS_LOB.FREETEMPORARY(l_cipher);
    DBMS_LOB.FREETEMPORARY(l_plain);
    DBMS_LOB.FREETEMPORARY(l_text);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_hex) = 1 THEN DBMS_LOB.FREETEMPORARY(l_hex); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_cipher) = 1 THEN DBMS_LOB.FREETEMPORARY(l_cipher); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_plain) = 1 THEN DBMS_LOB.FREETEMPORARY(l_plain); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_text) = 1 THEN DBMS_LOB.FREETEMPORARY(l_text); END IF;
      RAISE;
  END descripto_aes192;

  /**
   * @brief Decifra CLOB hexadecimal AES-192-CBC/PKCS#7.
    * @param p_cifra_clob Ciphertext hexadecimal.
   * @param p_chave Chave correspondente de 24 bytes UTF-8.
   * @param p_iv IV usado na cifra.
   * @param p_tipo VARCHAR2 ou NUMBER.
  * @return Texto recuperado em CLOB; NUMBER valida a representação decimal e a mantém como texto.
   */
  FUNCTION descripto_aes192(p_cifra_clob IN CLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2, p_tipo IN VARCHAR2 DEFAULT 'VARCHAR2') RETURN CLOB IS
    l_cipher BLOB;
    l_plain BLOB;
    l_result CLOB;
  BEGIN
    IF NVL(UPPER(p_tipo), '?') NOT IN ('VARCHAR2', 'NUMBER') THEN
      RAISE_APPLICATION_ERROR(-20012, 'p_tipo deve ser VARCHAR2 ou NUMBER.');
    END IF;
    l_cipher := aes_unhex_clob(p_cifra_clob);
    l_plain := aes_decrypt_blob(l_cipher, aes_key_raw(p_chave, 'Chave AES-192', 24), aes_key_raw(p_iv, 'IV'), 24);
    l_result := aes_blob_to_clob(l_plain);
    IF UPPER(p_tipo) = 'NUMBER' THEN
      IF DBMS_LOB.GETLENGTH(l_result) > 128 OR
         NOT REGEXP_LIKE(DBMS_LOB.SUBSTR(l_result, 128, 1),
           '^[+-]?([0-9]+([.][0-9]*)?|[.][0-9]+)([Ee][+-]?[0-9]+)?$') THEN
        RAISE_APPLICATION_ERROR(-20014, 'O conteúdo descriptografado não representa um NUMBER.');
      END IF;
    END IF;
    DBMS_LOB.FREETEMPORARY(l_cipher);
    DBMS_LOB.FREETEMPORARY(l_plain);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_cipher) = 1 THEN DBMS_LOB.FREETEMPORARY(l_cipher); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_plain) = 1 THEN DBMS_LOB.FREETEMPORARY(l_plain); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_result) = 1 THEN DBMS_LOB.FREETEMPORARY(l_result); END IF;
      RAISE;
  END descripto_aes192;

  /**
   * @brief Decifra BLOB binário AES-192-CBC/PKCS#7.
    * @param p_cifra_blob Ciphertext binário.
   * @param p_chave Chave correspondente de 24 bytes UTF-8.
   * @param p_iv IV usado na cifra.
   * @return Dados recuperados em BLOB.
   */
  FUNCTION descripto_aes192(p_cifra_blob IN BLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN BLOB IS
  BEGIN
    RETURN aes_decrypt_blob(p_cifra_blob, aes_key_raw(p_chave, 'Chave AES-192', 24), aes_key_raw(p_iv, 'IV'), 24);
  END descripto_aes192;

  /**
   * @brief Decifra RAW binário AES-192-CBC/PKCS#7.
    * @param p_cifra_raw Ciphertext binário.
   * @param p_chave Chave correspondente de 24 bytes UTF-8.
   * @param p_iv IV usado na cifra.
   * @return Dados recuperados em RAW.
   */
  FUNCTION descripto_aes192(p_cifra_raw IN RAW, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN RAW IS
    l_cipher BLOB;
    l_plain BLOB;
    l_length NUMBER;
    l_result RAW(32767);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_cipher, TRUE);
    IF p_cifra_raw IS NOT NULL THEN
      DBMS_LOB.WRITEAPPEND(l_cipher, UTL_RAW.LENGTH(p_cifra_raw), p_cifra_raw);
    END IF;
    l_plain := aes_decrypt_blob(l_cipher, aes_key_raw(p_chave, 'Chave AES-192', 24), aes_key_raw(p_iv, 'IV'), 24);
    l_length := DBMS_LOB.GETLENGTH(l_plain);
    IF l_length > 32767 THEN
      RAISE_APPLICATION_ERROR(-20013, 'Texto descriptografado excede o limite de retorno RAW.');
    END IF;
    IF l_length > 0 THEN l_result := DBMS_LOB.SUBSTR(l_plain, l_length, 1); END IF;
    DBMS_LOB.FREETEMPORARY(l_cipher);
    DBMS_LOB.FREETEMPORARY(l_plain);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_cipher) = 1 THEN DBMS_LOB.FREETEMPORARY(l_cipher); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_plain) = 1 THEN DBMS_LOB.FREETEMPORARY(l_plain); END IF;
      RAISE;
  END descripto_aes192;

  /**
   * @brief Cifra texto UTF-8 usando AES-256-CBC/PKCS#7.
    * @param p_texto_varchar2 Texto de entrada.
   * @param p_chave Chave com 32 bytes UTF-8.
   * @param p_iv IV de 16 bytes, único e imprevisível.
   * @return Ciphertext hexadecimal em VARCHAR2.
   */
  FUNCTION cripto_aes256(p_texto_varchar2 IN VARCHAR2, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    RETURN aes_encrypt_text_hex(p_texto_varchar2, p_chave, p_iv, 32);
  END cripto_aes256;

  /**
   * @brief Cifra CLOB UTF-8 usando AES-256-CBC/PKCS#7.
    * @param p_texto_clob CLOB de entrada.
   * @param p_chave Chave com 32 bytes UTF-8.
   * @param p_iv IV de 16 bytes, único e imprevisível.
   * @return Ciphertext hexadecimal em CLOB.
   */
  FUNCTION cripto_aes256(p_texto_clob IN CLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN CLOB IS
    l_plain BLOB;
    l_cipher BLOB;
    l_result CLOB;
    l_key RAW(32) := aes_key_raw(p_chave, 'Chave AES-256', 32);
    l_iv RAW(16) := aes_key_raw(p_iv, 'IV');
  BEGIN
    l_plain := aes_clob_to_blob(p_texto_clob);
    l_cipher := aes_encrypt_blob(l_plain, l_key, l_iv, 32);
    l_result := aes_hex_blob(l_cipher);
    DBMS_LOB.FREETEMPORARY(l_plain);
    DBMS_LOB.FREETEMPORARY(l_cipher);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_plain) = 1 THEN DBMS_LOB.FREETEMPORARY(l_plain); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_cipher) = 1 THEN DBMS_LOB.FREETEMPORARY(l_cipher); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_result) = 1 THEN DBMS_LOB.FREETEMPORARY(l_result); END IF;
      RAISE;
  END cripto_aes256;

  /**
   * @brief Cifra bytes BLOB usando AES-256-CBC/PKCS#7.
    * @param p_texto_blob BLOB de entrada.
   * @param p_chave Chave com 32 bytes UTF-8.
   * @param p_iv IV de 16 bytes, único e imprevisível.
   * @return Ciphertext binário em BLOB.
   */
  FUNCTION cripto_aes256(p_texto_blob IN BLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN BLOB IS
  BEGIN
    RETURN aes_encrypt_blob(p_texto_blob, aes_key_raw(p_chave, 'Chave AES-256', 32), aes_key_raw(p_iv, 'IV'), 32);
  END cripto_aes256;

  /**
   * @brief Cifra representação TM9 do NUMBER com AES-256-CBC/PKCS#7.
   * @param p_numero Número de entrada.
   * @param p_chave Chave com 32 bytes UTF-8.
   * @param p_iv IV de 16 bytes, único e imprevisível.
   * @return Ciphertext hexadecimal em VARCHAR2.
   */
  FUNCTION cripto_aes256(p_numero IN NUMBER, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN VARCHAR2 IS
  BEGIN
    RETURN aes_encrypt_text_hex(
      TO_CHAR(p_numero, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,'''),
      p_chave,
      p_iv,
      32
    );
  END cripto_aes256;

  /**
   * @brief Cifra bytes RAW usando AES-256-CBC/PKCS#7.
    * @param p_texto_raw Dados binários.
   * @param p_chave Chave com 32 bytes UTF-8.
   * @param p_iv IV de 16 bytes, único e imprevisível.
   * @return Ciphertext binário em RAW.
   */
  FUNCTION cripto_aes256(p_texto_raw IN RAW, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN RAW IS
    l_plain BLOB;
    l_cipher BLOB;
    l_length NUMBER;
    l_result RAW(32767);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_plain, TRUE);
    IF p_texto_raw IS NOT NULL THEN
      DBMS_LOB.WRITEAPPEND(l_plain, UTL_RAW.LENGTH(p_texto_raw), p_texto_raw);
    END IF;
    l_cipher := aes_encrypt_blob(l_plain, aes_key_raw(p_chave, 'Chave AES-256', 32), aes_key_raw(p_iv, 'IV'), 32);
    l_length := DBMS_LOB.GETLENGTH(l_cipher);
    IF l_length > 32767 THEN RAISE_APPLICATION_ERROR(-20011, 'Ciphertext excede o limite de retorno RAW.'); END IF;
    l_result := DBMS_LOB.SUBSTR(l_cipher, l_length, 1);
    DBMS_LOB.FREETEMPORARY(l_plain);
    DBMS_LOB.FREETEMPORARY(l_cipher);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_plain) = 1 THEN DBMS_LOB.FREETEMPORARY(l_plain); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_cipher) = 1 THEN DBMS_LOB.FREETEMPORARY(l_cipher); END IF;
      RAISE;
  END cripto_aes256;

  /**
   * @brief Decifra ciphertext hexadecimal AES-256-CBC/PKCS#7.
    * @param p_cifra_varchar2 Ciphertext hexadecimal.
   * @param p_chave Chave correspondente de 32 bytes UTF-8.
   * @param p_iv IV usado na cifra.
   * @param p_tipo VARCHAR2 ou NUMBER.
  * @return Texto recuperado; NUMBER valida a representação decimal e a retorna como texto.
   */
  FUNCTION descripto_aes256(p_cifra_varchar2 IN VARCHAR2, p_chave IN VARCHAR2, p_iv IN VARCHAR2, p_tipo IN VARCHAR2 DEFAULT 'VARCHAR2') RETURN VARCHAR2 IS
    l_hex CLOB;
    l_cipher BLOB;
    l_plain BLOB;
    l_text CLOB;
    l_result VARCHAR2(32767);
  BEGIN
    IF NVL(UPPER(p_tipo), '?') NOT IN ('VARCHAR2', 'NUMBER') THEN
      RAISE_APPLICATION_ERROR(-20012, 'p_tipo deve ser VARCHAR2 ou NUMBER.');
    END IF;
    DBMS_LOB.CREATETEMPORARY(l_hex, TRUE);
    IF p_cifra_varchar2 IS NOT NULL THEN DBMS_LOB.WRITEAPPEND(l_hex, LENGTH(p_cifra_varchar2), p_cifra_varchar2); END IF;
    l_cipher := aes_unhex_clob(l_hex);
    l_plain := aes_decrypt_blob(l_cipher, aes_key_raw(p_chave, 'Chave AES-256', 32), aes_key_raw(p_iv, 'IV'), 32);
    l_text := aes_blob_to_clob(l_plain);
    IF DBMS_LOB.GETLENGTH(l_text) > 32767 THEN
      RAISE_APPLICATION_ERROR(-20015, 'Texto descriptografado excede o limite VARCHAR2; use a sobrecarga CLOB.');
    END IF;
    l_result := DBMS_LOB.SUBSTR(l_text, 32767, 1);
    IF UPPER(p_tipo) = 'NUMBER' THEN
      IF NOT REGEXP_LIKE(l_result, '^[+-]?([0-9]+([.][0-9]*)?|[.][0-9]+)([Ee][+-]?[0-9]+)?$') THEN
        RAISE_APPLICATION_ERROR(-20014, 'O conteúdo descriptografado não representa um NUMBER.');
      END IF;
    END IF;
    DBMS_LOB.FREETEMPORARY(l_hex);
    DBMS_LOB.FREETEMPORARY(l_cipher);
    DBMS_LOB.FREETEMPORARY(l_plain);
    DBMS_LOB.FREETEMPORARY(l_text);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_hex) = 1 THEN DBMS_LOB.FREETEMPORARY(l_hex); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_cipher) = 1 THEN DBMS_LOB.FREETEMPORARY(l_cipher); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_plain) = 1 THEN DBMS_LOB.FREETEMPORARY(l_plain); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_text) = 1 THEN DBMS_LOB.FREETEMPORARY(l_text); END IF;
      RAISE;
  END descripto_aes256;

  /**
   * @brief Decifra CLOB hexadecimal AES-256-CBC/PKCS#7.
    * @param p_cifra_clob Ciphertext hexadecimal.
   * @param p_chave Chave correspondente de 32 bytes UTF-8.
   * @param p_iv IV usado na cifra.
   * @param p_tipo VARCHAR2 ou NUMBER.
  * @return Texto recuperado em CLOB; NUMBER valida a representação decimal e a mantém como texto.
   */
  FUNCTION descripto_aes256(p_cifra_clob IN CLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2, p_tipo IN VARCHAR2 DEFAULT 'VARCHAR2') RETURN CLOB IS
    l_cipher BLOB;
    l_plain BLOB;
    l_result CLOB;
  BEGIN
    IF NVL(UPPER(p_tipo), '?') NOT IN ('VARCHAR2', 'NUMBER') THEN
      RAISE_APPLICATION_ERROR(-20012, 'p_tipo deve ser VARCHAR2 ou NUMBER.');
    END IF;
    l_cipher := aes_unhex_clob(p_cifra_clob);
    l_plain := aes_decrypt_blob(l_cipher, aes_key_raw(p_chave, 'Chave AES-256', 32), aes_key_raw(p_iv, 'IV'), 32);
    l_result := aes_blob_to_clob(l_plain);
    IF UPPER(p_tipo) = 'NUMBER' THEN
      IF DBMS_LOB.GETLENGTH(l_result) > 128 OR
         NOT REGEXP_LIKE(DBMS_LOB.SUBSTR(l_result, 128, 1),
           '^[+-]?([0-9]+([.][0-9]*)?|[.][0-9]+)([Ee][+-]?[0-9]+)?$') THEN
        RAISE_APPLICATION_ERROR(-20014, 'O conteúdo descriptografado não representa um NUMBER.');
      END IF;
    END IF;
    DBMS_LOB.FREETEMPORARY(l_cipher);
    DBMS_LOB.FREETEMPORARY(l_plain);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_cipher) = 1 THEN DBMS_LOB.FREETEMPORARY(l_cipher); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_plain) = 1 THEN DBMS_LOB.FREETEMPORARY(l_plain); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_result) = 1 THEN DBMS_LOB.FREETEMPORARY(l_result); END IF;
      RAISE;
  END descripto_aes256;

  /**
   * @brief Decifra BLOB binário AES-256-CBC/PKCS#7.
    * @param p_cifra_blob Ciphertext binário.
   * @param p_chave Chave correspondente de 32 bytes UTF-8.
   * @param p_iv IV usado na cifra.
   * @return Dados recuperados em BLOB.
   */
  FUNCTION descripto_aes256(p_cifra_blob IN BLOB, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN BLOB IS
  BEGIN
    RETURN aes_decrypt_blob(p_cifra_blob, aes_key_raw(p_chave, 'Chave AES-256', 32), aes_key_raw(p_iv, 'IV'), 32);
  END descripto_aes256;

  /**
   * @brief Decifra RAW binário AES-256-CBC/PKCS#7.
    * @param p_cifra_raw Ciphertext binário.
   * @param p_chave Chave correspondente de 32 bytes UTF-8.
   * @param p_iv IV usado na cifra.
   * @return Dados recuperados em RAW.
   */
  FUNCTION descripto_aes256(p_cifra_raw IN RAW, p_chave IN VARCHAR2, p_iv IN VARCHAR2) RETURN RAW IS
    l_cipher BLOB;
    l_plain BLOB;
    l_length NUMBER;
    l_result RAW(32767);
  BEGIN
    DBMS_LOB.CREATETEMPORARY(l_cipher, TRUE);
    IF p_cifra_raw IS NOT NULL THEN DBMS_LOB.WRITEAPPEND(l_cipher, UTL_RAW.LENGTH(p_cifra_raw), p_cifra_raw); END IF;
    l_plain := aes_decrypt_blob(l_cipher, aes_key_raw(p_chave, 'Chave AES-256', 32), aes_key_raw(p_iv, 'IV'), 32);
    l_length := DBMS_LOB.GETLENGTH(l_plain);
    IF l_length > 32767 THEN RAISE_APPLICATION_ERROR(-20013, 'Texto descriptografado excede o limite de retorno RAW.'); END IF;
    IF l_length > 0 THEN l_result := DBMS_LOB.SUBSTR(l_plain, l_length, 1); END IF;
    DBMS_LOB.FREETEMPORARY(l_cipher);
    DBMS_LOB.FREETEMPORARY(l_plain);
    RETURN l_result;
  EXCEPTION
    WHEN OTHERS THEN
      IF DBMS_LOB.ISTEMPORARY(l_cipher) = 1 THEN DBMS_LOB.FREETEMPORARY(l_cipher); END IF;
      IF DBMS_LOB.ISTEMPORARY(l_plain) = 1 THEN DBMS_LOB.FREETEMPORARY(l_plain); END IF;
      RAISE;
  END descripto_aes256;
END criptopack;
/
