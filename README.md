# CRIPTOpack

O **CRIPTOpack** é uma package PL/SQL nativa para Oracle Database que fornece uma API completa para geração de Hashes, cálculo de CRC e Criptografia/Descriptografia simétrica (AES). 

O grande diferencial desta package é que ela **não depende da package `DBMS_CRYPTO`**, implementando a matemática e a lógica dos algoritmos diretamente em PL/SQL. Isso a torna ideal para ambientes onde as permissões de banco de dados são restritas e a concessão de grants para o `DBMS_CRYPTO` não é permitida ou desejada.

## 📁 Documentação e Exemplos

No repositório você encontrará:

* **Pasta `doc/`**: Contém o manual técnico completo ([`doc/MANUAL.md`](MANUAL.md)), detalhando todas as funções, sobrecargas de tipos de dados (`VARCHAR2`, `CLOB`, `BLOB`, `NUMBER`, `RAW`), tabela de erros e exceções, boas práticas de segurança, geração de IV e exemplos de integração com Triggers e Views.
* **Pasta `exemplo/`**: Contém um script PL/SQL ([`exemplo/demo_criptopack.sql`](demo_criptopack.sql)) de demonstração pronta para execução (por exemplo, via atalho F5 no Oracle SQL Developer). O script testa e exibe a saída de todas as funções de hash, CRC-32 e variações do AES-128/192/256 no console (`DBMS_OUTPUT`).

---

## 🚀 Funcionalidades

A package suporta a manipulação de diversos tipos de dados Oracle (`VARCHAR2`, `CLOB`, `BLOB`, `NUMBER` e `RAW`) e garante que o texto seja tratado em **UTF-8**. Hashes e ciphertexts (textos cifrados) em formato de texto são retornados em hexadecimal.

### Algoritmos de Hash e Checksum
*   **MD5**
*   **SHA-1**
*   **Família SHA-2:** SHA-256, SHA-384, SHA-512
*   **Família SHA-3:** SHA3-224, SHA3-256, SHA3-384, SHA3-512
*   **Checksum:** CRC-32/ISO-HDLC

### Criptografia Simétrica (AES)
Modo de operação **CBC** com padding **PKCS#7**.
*   **AES-128** (Requer chave de 16 bytes)
*   **AES-192** (Requer chave de 24 bytes)
*   **AES-256** (Requer chave de 32 bytes)
*   *Nota:* O vetor de inicialização (IV) deve ter sempre 16 bytes.

---

## 📦 Dependências

O **CRIPTOpack** é totalmente independente de bibliotecas externas, Java Stored Procedures ou da package `DBMS_CRYPTO`. Ele utiliza apenas as packages nativas e padrão do Oracle que geralmente já estão acessíveis a todos os usuários:

*   `DBMS_LOB`: Para manipulação e conversão de LOBs (`CLOB`, `BLOB`).
*   `UTL_RAW`: Para manipulação de bytes e dados binários.
*   `UTL_I18N`: Para conversões seguras de string para UTF-8.

---

## 🛠️ Como Instalar

A instalação consiste na compilação da especificação (Spec) e do corpo (Body) da package no seu banco de dados Oracle.

1. Faça o download dos arquivos [`src/criptopack.pks`](src/criptopack.pks) (Spec) e [`src/criptopack.pkb`](src/criptopack.pkb)  (Body).
2. Conecte-se ao seu banco de dados Oracle usando sua IDE de banco de dados preferida (como SQL Developer, DBeaver, PL/SQL Developer) ou via linha de comando (SQL*Plus).
3. Compile **primeiro** a especificação executando o script `criptopack.pks`.
   ```sql
   @criptopack.pks
   ```
4. Em seguida, compile o corpo da package executando o script `criptopack.pkb`.
   ```sql
   @criptopack.pkb
   ```

Pronto! A package `criptopack` estará disponível para uso no schema onde os scripts foram executados.

---

## 💡 Exemplos Rápidos de Uso

### 1. Gerando um Hash (SHA-256)
```sql
DECLARE
  v_hash VARCHAR2(64);
BEGIN
  v_hash := criptopack.hash_sha256('Minha senha super secreta');
  DBMS_OUTPUT.PUT_LINE('SHA-256: ' || v_hash);
END;
/
```

### 2. Criptografando e Descriptografando com AES-256
Para chamadas de criptografia AES, é altamente recomendável o uso de **Named Notation** (parâmetros nomeados) para evitar ambiguidades de conversão implícita de tipos.

```sql
DECLARE
  v_texto   VARCHAR2(100) := 'Dados confidenciais';
  v_chave   VARCHAR2(32)  := 'ChaveSecretaDe32BytesExataAqui!!';
  v_iv      VARCHAR2(16)  := 'VetorInic16Bytes';
  v_cifrado VARCHAR2(4000);
  v_decript VARCHAR2(4000);
BEGIN
  -- Criptografar
  v_cifrado := criptopack.cripto_aes256(
    p_texto_varchar2 => v_texto,
    p_chave          => v_chave,
    p_iv             => v_iv
  );

  -- Descriptografar
  v_decript := criptopack.descripto_aes256(
    p_cifra_varchar2 => v_cifrado,
    p_chave          => v_chave,
    p_iv             => v_iv
  );

  DBMS_OUTPUT.PUT_LINE('Cifrado: ' || v_cifrado);
  DBMS_OUTPUT.PUT_LINE('Decifrado: ' || v_decript);
END;
/
```

Para uma demonstração completa com todos os overloads e tipos de dados, execute o script disponível na pasta `exemplo/`.

---

## ⚠️ Recomendações de Segurança
* **Hashes Rápidos vs. Senhas:** Embora a package forneça SHA-2/SHA-3 rápidos, estes algoritmos não devem ser usados sozinhos para armazenamento seguro de senhas. Para senhas de usuários, utilize funções de derivação de chaves (KDF) com salt (ex: PBKDF2, Bcrypt ou Argon2).
* **Vetor de Inicialização (IV):** Ao usar o modo AES-CBC, utilize um IV único e imprevisível para cada operação de cifragem.
* **Autenticidade:** O modo CBC não fornece autenticação. Para proteger a integridade dos dados cifrados (evitando ataques de manipulação), implemente um código de autenticação de mensagem (MAC) separadamente.

---

## 📄 Licença

Este projeto é licenciado sob a Licença **GPLv3** (GNU General Public License v3.0). Consulte o arquivo de licença no repositório para obter mais detalhes.

---

## 📚 Referências Bibliográficas

Os algoritmos e padrões implementados nesta package seguem estritamente as especificações oficiais descritas na literatura técnica e em normas internacionais:

1. **MD5 (Message-Digest Algorithm 5)**
   * Rivest, R. (1992). *The MD5 Message-Digest Algorithm*. RFC 1321, Internet Engineering Task Force (IETF). [https://datatracker.ietf.org/doc/html/rfc1321](https://datatracker.ietf.org/doc/html/rfc1321)

2. **SHA-1 e Família SHA-2 (SHA-256, SHA-384, SHA-512)**
   * National Institute of Standards and Technology (NIST). (2015). *Secure Hash Standard (SHS)*. Federal Information Processing Standards Publication (FIPS PUB) 180-4. [https://doi.org/10.6028/NIST.FIPS.180-4](https://doi.org/10.6028/NIST.FIPS.180-4)

3. **Família SHA-3 (SHA3-224, SHA3-256, SHA3-384, SHA3-512)**
   * National Institute of Standards and Technology (NIST). (2015). *SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions*. Federal Information Processing Standards Publication (FIPS PUB) 202. [https://doi.org/10.6028/NIST.FIPS.202](https://doi.org/10.6028/NIST.FIPS.202)

4. **CRC-32 (Cyclic Redundancy Check / ISO-HDLC)**
   * ITU-T Recommendation V.42 (1998). *Error-correcting procedures for DCEs using asynchronous-to-synchronous conversion*. International Telecommunication Union.

5. **AES (Advanced Encryption Standard - Rijndael)**
   * National Institute of Standards and Technology (NIST). (2001). *Advanced Encryption Standard (AES)*. Federal Information Processing Standards Publication (FIPS PUB) 197. [https://doi.org/10.6028/NIST.FIPS.197](https://doi.org/10.6028/NIST.FIPS.197)

6. **Modo de Operação CBC (Cipher Block Chaining)**
   * Dworkin, M. (2001). *Recommendation for Block Cipher Modes of Operation: Methods and Techniques*. NIST Special Publication 800-38A, National Institute of Standards and Technology. [https://doi.org/10.6028/NIST.SP.800-38A](https://doi.org/10.6028/NIST.SP.800-38A)

7. **Preenchimento PKCS #7 (Padding Scheme)**
   * Kaliski, B. (1998). *PKCS #7: Cryptographic Message Syntax Version 1.5*. RFC 2315, Internet Engineering Task Force (IETF). [https://datatracker.ietf.org/doc/html/rfc2315](https://datatracker.ietf.org/doc/html/rfc2315)
