# Manual Completo - CRIPTOpack

O **CRIPTOpack** é uma package nativa em PL/SQL para Oracle Database que provê funções de Hash, Checksum e Criptografia simétrica (AES), sem qualquer dependência da package `DBMS_CRYPTO`.

Este manual descreve o processo de instalação, o uso de todas as funções disponíveis, padrões de segurança, exemplos práticos de integração e tratamento de erros.

---

## 1. Instruções Detalhadas de Instalação

A instalação da package `CRIPTOpack` é simples e não requer privilégios especiais de DBA além daqueles necessários para criar objetos (packages) no seu próprio schema (ex: `CREATE PROCEDURE`).

### Passo a Passo

1. **Obtenha os arquivos fonte:**
   Você precisará de dois arquivos:
   * `criptopack.pks` (Especificação / Spec)
   * `criptopack.pkb` (Corpo / Body)

2. **Conecte-se ao Banco de Dados:**
   Abra sua ferramenta de banco de dados preferida (SQL Developer, DBeaver, PL/SQL Developer, SQL*Plus) e conecte-se ao schema onde deseja instalar a package.

3. **Compile a Especificação (PKS):**
   É obrigatório compilar a especificação primeiro.
   No SQL*Plus ou na aba de script da sua IDE, execute o conteúdo do arquivo `.pks`:
   ```sql
   @caminho/do/arquivo/criptopack.pks
   ```

4. **Compile o Corpo (PKB):**
   Após a especificação ser compilada com sucesso (sem erros), compile o corpo.
   ```sql
   @caminho/do/arquivo/criptopack.pkb
   ```

5. **(Opcional) Conceda Permissões:**
   Se outros usuários do banco precisarem usar a package, conceda o privilégio de execução:
   ```sql
   GRANT EXECUTE ON criptopack TO nome_do_outro_usuario;
   ```

---

## 2. Funções de Hash e Checksum

Todas as funções de Hash e Checksum possuem sobrecargas para suportar os tipos de dados mais comuns: `VARCHAR2`, `NUMBER`, `CLOB` e `BLOB`. O retorno será sempre um `VARCHAR2` contendo o valor em hexadecimal minúsculo.

### 2.1. MD5 (`hash_md5`)
Calcula o hash MD5 (32 caracteres hexadecimais). *Atenção: Considerado inseguro para fins criptográficos modernos.*

```sql
DECLARE
  v_varchar2 VARCHAR2(32);
  v_numero   VARCHAR2(32);
  v_clob     VARCHAR2(32);
  v_blob     VARCHAR2(32);
BEGIN
  -- Exemplo com VARCHAR2
  v_varchar2 := criptopack.hash_md5('Texto Simples');
  
  -- Exemplo com NUMBER (converte para representação decimal TM9 internamente)
  v_numero := criptopack.hash_md5(12345.67);
  
  -- Exemplo com CLOB
  v_clob := criptopack.hash_md5(TO_CLOB('Texto longo em CLOB...'));
  
  -- Exemplo com BLOB
  v_blob := criptopack.hash_md5(UTL_RAW.CAST_TO_RAW('Bytes puros'));
  
  DBMS_OUTPUT.PUT_LINE('MD5 VARCHAR2: ' || v_varchar2);
END;
/
```

### 2.2. Família SHA-1 e SHA-2 (`hash_sha1`, `hash_sha256`, `hash_sha384`, `hash_sha512`)
Calcula hashes seguros para verificação de integridade.

```sql
BEGIN
  -- SHA-1 (40 caracteres hex)
  DBMS_OUTPUT.PUT_LINE('SHA1: ' || criptopack.hash_sha1('Teste SHA1'));
  
  -- SHA-256 (64 caracteres hex) - Recomendado para uso geral
  DBMS_OUTPUT.PUT_LINE('SHA256: ' || criptopack.hash_sha256('Teste SHA256'));
  
  -- SHA-384 (96 caracteres hex)
  DBMS_OUTPUT.PUT_LINE('SHA384: ' || criptopack.hash_sha384(TO_CLOB('Teste SHA384 CLOB')));
  
  -- SHA-512 (128 caracteres hex)
  DBMS_OUTPUT.PUT_LINE('SHA512: ' || criptopack.hash_sha512(99999.99));
END;
/
```

### 2.3. Família SHA-3 (`hash_sha3_224`, `hash_sha3_256`, `hash_sha3_384`, `hash_sha3_512`)
Implementação do padrão mais recente de hashing (Keccak).

```sql
BEGIN
  DBMS_OUTPUT.PUT_LINE('SHA3-224: ' || criptopack.hash_sha3_224('Segurança Moderna'));
  DBMS_OUTPUT.PUT_LINE('SHA3-256: ' || criptopack.hash_sha3_256('Segurança Moderna'));
  DBMS_OUTPUT.PUT_LINE('SHA3-384: ' || criptopack.hash_sha3_384('Segurança Moderna'));
  DBMS_OUTPUT.PUT_LINE('SHA3-512: ' || criptopack.hash_sha3_512('Segurança Moderna'));
END;
/
```

### 2.4. CRC-32 (`hash_crc32`)
Calcula o Cyclic Redundancy Check de 32 bits (ISO-HDLC). Retorna 8 caracteres hex.

```sql
BEGIN
  DBMS_OUTPUT.PUT_LINE('CRC-32: ' || criptopack.hash_crc32('ArquivoDeDados.txt'));
  DBMS_OUTPUT.PUT_LINE('CRC-32 (Num): ' || criptopack.hash_crc32(1024));
END;
/
```

---

## 3. Funções de Criptografia (AES)

A criptografia usa o algoritmo AES no modo CBC com preenchimento PKCS#7.
**Requisitos importantes:**
* O Vetor de Inicialização (`p_iv`) deve ter **SEMPRE 16 bytes**.
* A chave deve ter tamanho exato conforme a versão do AES:
  * AES-128: Chave de 16 bytes.
  * AES-192: Chave de 24 bytes.
  * AES-256: Chave de 32 bytes.

### 3.1. AES-128 (Uso com VARCHAR2 e NUMBER)
Demonstração das funções `cripto_aes128` e `descripto_aes128`.

```sql
DECLARE
  v_chave   VARCHAR2(16) := '1234567890123456'; -- Exatamente 16 bytes
  v_iv      VARCHAR2(16) := 'abcdefghijklmnop'; -- Exatamente 16 bytes
  
  v_cifra_txt VARCHAR2(4000);
  v_cifra_num VARCHAR2(4000);
BEGIN
  -- Criptografar VARCHAR2
  v_cifra_txt := criptopack.cripto_aes128('Texto Secreto', v_chave, v_iv);
  DBMS_OUTPUT.PUT_LINE('Cifrado (TXT): ' || v_cifra_txt);
  
  -- Descriptografar VARCHAR2
  DBMS_OUTPUT.PUT_LINE('Decifrado (TXT): ' || criptopack.descripto_aes128(v_cifra_txt, v_chave, v_iv));

  -- Criptografar NUMBER
  v_cifra_num := criptopack.cripto_aes128(500.25, v_chave, v_iv);
  
  -- Descriptografar NUMBER (Note o parâmetro p_tipo = 'NUMBER')
  DBMS_OUTPUT.PUT_LINE('Decifrado (NUM): ' || criptopack.descripto_aes128(v_cifra_num, v_chave, v_iv, 'NUMBER'));
END;
/
```

### 3.2. AES-192 (Uso com CLOB)
Para grandes blocos de texto (acima do limite do VARCHAR2).

```sql
DECLARE
  v_chave   VARCHAR2(24) := '123456789012345678901234'; -- Exatamente 24 bytes
  v_iv      VARCHAR2(16) := 'abcdefghijklmnop';       -- Exatamente 16 bytes
  
  v_clob_original CLOB := TO_CLOB('Um texto muito longo que precisa ser protegido de forma eficiente em um banco de dados.');
  v_clob_cifrado  CLOB;
  v_clob_decifrado CLOB;
BEGIN
  -- Criptografar CLOB
  v_clob_cifrado := criptopack.cripto_aes192(v_clob_original, v_chave, v_iv);
  
  -- Descriptografar CLOB
  v_clob_decifrado := criptopack.descripto_aes192(v_clob_cifrado, v_chave, v_iv);
  
  DBMS_OUTPUT.PUT_LINE('CLOB Decifrado com sucesso.');
END;
/
```

### 3.3. AES-256 (Uso com BLOB e RAW)
Segurança máxima, útil para proteger arquivos (BLOB) ou pequenos dados binários (RAW). Os dados permanecem em formato binário, sem conversão para hexadecimal.

```sql
DECLARE
  v_chave   VARCHAR2(32) := '12345678901234567890123456789012'; -- Exatamente 32 bytes
  v_iv      VARCHAR2(16) := 'abcdefghijklmnop';                 -- Exatamente 16 bytes
  
  v_raw_original  RAW(2000) := UTL_RAW.CAST_TO_RAW('Dados binarios puros RAW');
  v_blob_original BLOB;
  
  v_raw_cifrado  RAW(2000);
  v_blob_cifrado BLOB;
BEGIN
  -- Setup BLOB
  DBMS_LOB.CREATETEMPORARY(v_blob_original, TRUE);
  DBMS_LOB.WRITEAPPEND(v_blob_original, UTL_RAW.LENGTH(v_raw_original), v_raw_original);

  -- 1. Criptografia RAW
  v_raw_cifrado := criptopack.cripto_aes256(v_raw_original, v_chave, v_iv);
  DBMS_OUTPUT.PUT_LINE('Descripto RAW: ' || UTL_RAW.CAST_TO_VARCHAR2(criptopack.descripto_aes256(v_raw_cifrado, v_chave, v_iv)));

  -- 2. Criptografia BLOB
  v_blob_cifrado := criptopack.cripto_aes256(v_blob_original, v_chave, v_iv);
  
  DBMS_OUTPUT.PUT_LINE('BLOB AES-256 Criptografado com sucesso (Tamanho: ' || DBMS_LOB.GETLENGTH(v_blob_cifrado) || ' bytes)');
  
  DBMS_LOB.FREETEMPORARY(v_blob_original);
END;
/
```

---

## 4. Boas Práticas de Segurança e Geração de IV/Chaves

### 4.1. Geração Prática do IV (Vetor de Inicialização)
No modo AES-CBC, **nunca reaproveite o mesmo IV** para cripografar dados diferentes com a mesma chave. O IV deve ter exatamente 16 bytes, ser imprevisível e **único por operação**.

> **Nota:** O IV não é um segredo! Ele pode (e deve) ser armazenado no banco de dados junto ao texto cifrado para permitir a descriptografia futura.

Uma forma recomendada de gerar IVs únicos no Oracle sem requerer pacotes restritos é utilizando `SYS_GUID()`:

```sql
FUNCTION gerar_iv_unico RETURN VARCHAR2 IS
BEGIN
  -- SYS_GUID() gera 16 bytes RAW representados por 32 caracteres HEX.
  -- Convertemos esses 16 bytes RAW em texto UTF-8 de 16 caracteres.
  RETURN UTL_RAW.CAST_TO_VARCHAR2(HEXTORAW(SYS_GUID()));
END;
/
```

### 4.2. Armazenamento Seguro de Chaves
* **Evite Hardcode:** Nunca insira chaves diretamente nos scripts SQL ou no código das triggers.
* **Armazenamento:** Utilize um contexto de aplicação (`CLIENT_CONTEXT`), tabelas de parâmetros criptografadas com acesso restrito via pacotes `DEFINER'S RIGHTS`, ou insira a chave a partir de variáveis de ambiente passadas pela aplicação externa.

### 4.3. Senhas vs. Hashes Rápidos
Embora o `CRIPTOpack` disponibilize SHA-256 e SHA-3, **não utilize estes algoritmos diretamente para armazenamento de senhas de usuários**. Por serem muito rápidos, são vulneráveis a ataques de força bruta e rainbow tables. Para armazenamento de senhas, recomenda-se o uso de algoritmos de derivação de chaves (KDF) com salt (ex: PBKDF2, Bcrypt ou Argon2).

---

## 5. Exemplo de Integração em Banco (Triggers e Views)

Cenário real: Criptografar automaticamente a coluna `CPF` de uma tabela de clientes na inserção/atualização, e expor uma `VIEW` transparente para leitura.

### 5.1. Criação da Tabela com coluna para o IV
```sql
CREATE TABLE tb_clientes (
  id_cliente   NUMBER PRIMARY KEY,
  nome_cliente VARCHAR2(100),
  cpf_cifrado  VARCHAR2(100),
  iv_cpf       VARCHAR2(16)
);
```

### 5.2. Trigger para Criptografia Automática
```sql
CREATE OR REPLACE TRIGGER trg_tb_clientes_biu
BEFORE INSERT OR UPDATE OF cpf_cifrado ON tb_clientes
FOR EACH ROW
DECLARE
  c_chave CONSTANT VARCHAR2(32) := 'ChaveMuitoSeguraCom32BytesExatos!'; -- Exemplo
BEGIN
  -- Criptografa apenas se um novo CPF não-nulo for fornecido
  IF :NEW.cpf_cifrado IS NOT NULL AND (:OLD.cpf_cifrado IS NULL OR :NEW.cpf_cifrado <> :OLD.cpf_cifrado) THEN
    -- Gerar um IV imprevisível de 16 bytes via SYS_GUID
    :NEW.iv_cpf := UTL_RAW.CAST_TO_VARCHAR2(HEXTORAW(SYS_GUID()));
    
    -- Substitui o texto claro pelo valor cifrado
    :NEW.cpf_cifrado := criptopack.cripto_aes256(:NEW.cpf_cifrado, c_chave, :NEW.iv_cpf);
  END IF;
END;
/
```

### 5.3. View para Leitura Descriptografada
```sql
CREATE OR REPLACE VIEW vw_clientes AS
SELECT 
  id_cliente,
  nome_cliente,
  criptopack.descripto_aes256(
    cpf_cifrado, 
    'ChaveMuitoSeguraCom32BytesExatos!', 
    iv_cpf
  ) AS cpf
FROM tb_clientes;
```

---

## 6. Tabela de Exceções e Tratamento de Erros

A package dispara exceções com códigos entre `-20001` e `-20016` utilizando `RAISE_APPLICATION_ERROR`.

| Código Error | Descrição / Causa |
| :--- | :--- |
| **ORA-20001** | Blocos AES ou tamanho de chave inválido (exige blocos de 16 bytes e chaves de 16, 24 ou 32 bytes). |
| **ORA-20002** | Incompatibilidade de tamanho entre os blocos AES durante operação XOR. |
| **ORA-20003** | Tamanho de chave AES incorreto para a variante chamada. |
| **ORA-20004** | O Vetor de Inicialização (IV) do modo CBC não possui exatamente 16 bytes UTF-8. |
| **ORA-20005** | O ciphertext AES-CBC informado não contém blocos múltiplos de 16 bytes. |
| **ORA-20006** | Padding PKCS#7 inválido. Ocorre geralmente quando a **chave ou o IV estão incorretos**. |
| **ORA-20007** | O ciphertext em formato hexadecimal possui uma quantidade ímpar de caracteres. |
| **ORA-20008** | Falha de conversão do conteúdo CLOB para a codificação UTF-8. |
| **ORA-20009** | Os bytes descriptografados do BLOB não formam uma string UTF-8 válida. |
| **ORA-20010** | Parâmetro de chave ou IV não possui a quantidade esperada de bytes UTF-8. |
| **ORA-20011** | O resultado cifrado excede o limite máximo suportado pelo tipo `RAW` (32.767 bytes). |
| **ORA-20012** | O parâmetro `p_tipo` informado é inválido (deve ser 'VARCHAR2' ou 'NUMBER'). |
| **ORA-20013** | O texto descriptografado excede o limite máximo de retorno para `RAW`. |
| **ORA-20014** | O contéudo descriptografado com o tipo 'NUMBER' informado não é um número decimal válido. |
| **ORA-20015** | O texto descriptografado excede os 32.767 bytes do `VARCHAR2`. Use a sobrecarga `CLOB`. |
| **ORA-20016** | O texto cifrado excede os 32.767 bytes do `VARCHAR2`. Use a sobrecarga `CLOB`. |

### Exemplo de Captura de Erros em PL/SQL
```sql
DECLARE
  e_padding_invalido EXCEPTION;
  PRAGMA EXCEPTION_INIT(e_padding_invalido, -20006);
  
  v_resultado VARCHAR2(4000);
BEGIN
  -- Tentativa de descriptografar com chave errada
  v_resultado := criptopack.descripto_aes128(
                   'A1B2C3D4E5F607080900112233445566', 
                   'ChaveIncorreta12', 
                   'IV_Errado_123456'
                 );
EXCEPTION
  WHEN e_padding_invalido THEN
    DBMS_OUTPUT.PUT_LINE('Erro: Chave ou IV incorretos fornecidos para a descriptografia.');
  WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('Erro inesperado: ' || SQLERRM);
END;
/
```

---

## 7. Performance e Considerações Arquiteturais

* **Portabilidade vs. Velocidade:** Por ser uma solução em **PL/SQL nativo e puro** (sem o uso de bibliotecas compiladas em C do `DBMS_CRYPTO`), o `CRIPTOpack` oferece total autonomia e portabilidade em ambientes restritos.
* **Volume de Dados:** Para colunas relacionais, registros pontuais e LOBs moderados, a performance é excelente. Caso precise cifrar arquivos LOB com centenas de megabytes ou gigabytes em lote, recomenda-se realizar o processamento em janelas/lotes para gerenciar o uso de memória temporária (`DBMS_LOB.CREATETEMPORARY`).

---
*Fim do Manual.*
