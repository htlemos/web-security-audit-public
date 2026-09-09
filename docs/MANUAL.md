# Web Security Audit 1.0.2

## Manual de instalação e utilização

## 1. Objetivo

O Web Security Audit executa verificações externas e não autenticadas sobre serviços web. A versão 1.0.2 utiliza um único motor autónomo, `web-security-audit.py`.

Os domínios, características dos alvos e exceções de cada projeto são definidos em `audit-config.json`. O perfil de auditoria distribuído com o pacote é `profiles/profile-web-security-external.json`.

Para cada execução, o motor produz:

- `WEB_SECURITY_AUDIT.html`: relatório navegável com resultados e evidências;
- `audit-results.json`: resultados estruturados em JSON;
- `executive-summary.csv`: resumo para Excel, Power BI ou tratamento automatizado;
- `details/<domínio>/`: evidências recolhidas pelas ferramentas.

## 2. Conteúdo do pacote

```text
web-security-audit-1.0.2/
├── web-security-audit.py
├── install.sh
├── README.md
├── SHA256SUMS.txt
├── profiles/
│   └── profile-web-security-external.json
├── config/
│   └── audit-config.example.json
└── docs/
    ├── MANUAL.md
    └── CHANGELOG.md
```

Para utilizar a aplicação são relevantes:

- `web-security-audit.py`: motor da auditoria;
- `install.sh`: validação inicial do ambiente e preparação da configuração;
- `profiles/profile-web-security-external.json`: controlos e critérios do perfil externo;
- `config/audit-config.example.json`: configuração de exemplo;
- `README.md`: início rápido;
- `docs/MANUAL.md`: manual de utilização;
- `docs/CHANGELOG.md`: alterações entre versões.

## 3. Requisitos

- Linux, WSL2 ou ambiente equivalente;
- Python 3;
- curl;
- OpenSSL;
- testssl.sh;
- Nmap;
- Nikto, opcional e configurável.

A instalação das dependências deve respeitar o gestor de pacotes e as políticas do ambiente onde a auditoria será executada.

## 4. Verificar a integridade do pacote

Antes de extrair o ZIP, validar o checksum disponibilizado com a release:

```bash
sha256sum -c web-security-audit-1.0.2.zip.sha256
```

Resultado esperado:

```text
web-security-audit-1.0.2.zip: OK
```

Depois de extrair o pacote, é possível validar os ficheiros internos:

```bash
cd web-security-audit-1.0.2
sha256sum -c SHA256SUMS.txt
```

## 5. Instalação

```bash
unzip web-security-audit-1.0.2.zip
cd web-security-audit-1.0.2
chmod 750 install.sh
./install.sh
```

O `install.sh`:

1. valida a presença dos comandos necessários;
2. aplica permissão de execução ao motor;
3. cria `audit-config.json` a partir de `config/audit-config.example.json`, caso ainda não exista;
4. verifica a sintaxe do motor;
5. valida a configuração e o perfil.

Resultado esperado no final:

```text
Web Security Audit 1.0.2: configuration and profile are valid.
Installation validation successful.
```

Se `audit-config.json` já existir, o instalador não deve substituir a configuração existente.

## 6. Configuração

O ficheiro operacional é:

```text
audit-config.json
```

O ficheiro deve conter os metadados, os alvos e os parâmetros de execução. Os domínios devem existir apenas neste ficheiro e nunca no motor ou no perfil.

### Exemplo

```json
{
  "metadata": {
    "project": "Example Project"
  },
  "targets": [
    {
      "domain": "example.org",
      "port": 443,
      "platform": "Web application",
      "service_type": "WEB",
      "certificate_policy": {
        "minimum_validation": "OV",
        "wildcard_allowed": false
      },
      "http80_policy": {
        "allow_service": false
      }
    }
  ],
  "tests": {
    "curl": {
      "timeout": 30,
      "connect_timeout": 10,
      "max_redirects": 5
    },
    "openssl": {
      "timeout": 30
    },
    "testssl": {
      "timeout": 900
    },
    "nmap": {
      "enabled": true,
      "timeout": 300
    },
    "nikto": {
      "enabled": true,
      "timeout": 60
    }
  }
}
```

### Campos do target

- `domain`: nome DNS a auditar;
- `port`: porta HTTPS, normalmente 443;
- `platform`: identificação informativa da plataforma;
- `service_type`: tipo de serviço, atualmente `WEB`;
- `minimum_validation`: nível mínimo aceite para o certificado, `DV`, `OV` ou `EV`;
- `wildcard_allowed`: quando verdadeiro, um wildcard autorizado é classificado como `PROFILE_EXCEPTION`;
- `allow_service`: quando verdadeiro, um comportamento penalizável em HTTP/80 explicitamente permitido é classificado como `PROFILE_EXCEPTION`.

### Ferramentas e tempos limite

- `curl`: transporte HTTPS, redirecionamentos, cabeçalhos e conteúdo;
- `openssl`: cadeia, hostname, validade e dados do certificado;
- `testssl`: protocolos e cifras;
- `nmap`: evidência complementar;
- `nikto`: evidência complementar e informativa.

Aumentar um timeout pode ser necessário em redes lentas ou alvos com resposta demorada. Desativar Nmap ou Nikto reduz o tempo de execução, mas também reduz a evidência complementar disponível.

## 7. Validar a configuração

Executar antes de cada auditoria ou depois de alterar a configuração ou o perfil:

```bash
python3 web-security-audit.py \
  --validate-only \
  -c audit-config.json \
  -p profiles/profile-web-security-external.json
```

A validação confirma a estrutura mínima da configuração e a presença dos controlos exigidos pelo motor. A validação não executa a auditoria aos alvos.

## 8. Executar uma auditoria

```bash
python3 web-security-audit.py \
  -c audit-config.json \
  -p profiles/profile-web-security-external.json \
  -o reports/audit-output
```

Durante a execução, a consola apresenta as dez fases de recolha para cada domínio. No final apresenta:

- número de domínios auditados;
- distribuição por estado;
- ranking por Technical Debt;
- Compliance e Exposure por domínio;
- caminho para o relatório HTML.

A diretoria indicada em `-o` contém o relatório, os resultados estruturados e as evidências.

## 9. Resultados produzidos

### WEB_SECURITY_AUDIT.html

Relatório principal para consulta humana. Inclui:

- explicação das métricas;
- grupos de causas principais;
- resumo por domínio;
- findings ordenados por resultado;
- ligação entre cada finding e a respetiva evidência;
- destaque das linhas de evidência associadas aos resultados.

Navegação principal:

```text
Domain Summary -> Domain -> Finding -> Evidence
```

### audit-results.json

Resultado estruturado por domínio, incluindo estado, métricas e findings. Pode ser utilizado para integração ou processamento automatizado.

### executive-summary.csv

Resumo tabular por domínio, apropriado para Excel, Power BI ou análise comparativa.

### details/<domínio>/

Contém os ficheiros de evidência recolhidos por curl, OpenSSL, testssl, Nmap, Nikto e pelas verificações internas do motor.

## 10. Estados

- `PASS`: controlo cumprido;
- `FAIL`: incumprimento de um requisito obrigatório;
- `INCONCLUSIVE`: não foi possível obter evidência suficiente;
- `RECOMMENDATION`: oportunidade de melhoria num controlo recomendado;
- `PROFILE_EXCEPTION`: exceção explicitamente autorizada na configuração;
- `NOT_APPLICABLE`: controlo dependente não aplicável;
- `INFORMATIONAL`: observação sem impacto na conformidade.

## 11. Métricas

### Technical Debt Score

Começa em zero e acumula penalizações negativas:

- falha obrigatória: -15;
- controlo obrigatório inconclusivo: -5;
- recomendação: -2;
- controlo recomendado inconclusivo: -1.

Quanto mais próximo de zero, menor a dívida técnica observada.

### Compliance Score

Percentagem de controlos obrigatórios aplicáveis que passaram. `NOT_APPLICABLE`, `PROFILE_EXCEPTION` e `INFORMATIONAL` ficam excluídos do denominador.

### Exposure Score

Começa em 100 e deduz por falhas, segundo a severidade:

- `CRITICAL`: -10;
- `HIGH`: -6;
- `MEDIUM`: -3;
- `LOW`: -1.

Quanto maior o valor, menor a exposição observada.

## 12. Perfil de auditoria

O perfil distribuído é:

```text
profiles/profile-web-security-external.json
```

O perfil contém:

- controlos e valores esperados;
- requisitos obrigatórios e recomendados;
- severidades;
- diretivas de Permissions-Policy;
- allowlist de cifras TLS 1.2 e TLS 1.3;
- política de HTTP/80.

Para criar um perfil personalizado:

```bash
cp profiles/profile-web-security-external.json \
   profiles/profile-custom.json
```

Validar o perfil personalizado:

```bash
python3 web-security-audit.py \
  --validate-only \
  -c audit-config.json \
  -p profiles/profile-custom.json
```

Executar com o perfil personalizado:

```bash
python3 web-security-audit.py \
  -c audit-config.json \
  -p profiles/profile-custom.json \
  -o reports/audit-custom
```

Não alterar o perfil distribuído sem guardar uma cópia. Uma alteração incorreta ao ID ou ao tipo de teste pode impedir a validação ou tornar um controlo não avaliável.

## 13. Resolução de problemas

### testssl não encontrado

Confirmar:

```bash
command -v testssl.sh || command -v testssl
```

O comando deve devolver o caminho para o executável.

### Nikto não está instalado

O instalador apresenta um aviso. Instalar Nikto ou desativá-lo em `audit-config.json`:

```json
"nikto": {
  "enabled": false,
  "timeout": 60
}
```

### Nikto termina por timeout

O test pode ficar `INFORMATIONAL` com estado `INCOMPLETE_SCAN`. Este resultado não penaliza a conformidade.

### Resposta bloqueada por CDN ou WAF

Quando a resposta não permite observar a aplicação real, os controlos associados podem ficar `INCONCLUSIVE`. O resultado deve ser revisto com a equipa responsável pelo serviço ou a partir de um ponto de teste autorizado.

### HTTP/80 é intencional

Definir no respetivo target:

```json
"http80_policy": {
  "allow_service": true
}
```

A exceção deve estar autorizada e documentada para o projeto.

### Wildcard é autorizado

Definir no respetivo target:

```json
"certificate_policy": {
  "minimum_validation": "OV",
  "wildcard_allowed": true
}
```

### O instalador não encontra a configuração de exemplo

Confirmar que o pacote preserva esta localização:

```text
config/audit-config.example.json
```

Executar o instalador a partir da raiz da diretoria extraída:

```bash
cd web-security-audit-1.0.2
./install.sh
```

### Permissão negada

```bash
chmod 750 install.sh web-security-audit.py
```

### A configuração não é válida

Executar `--validate-only` e rever a mensagem apresentada. Comparar `audit-config.json` com `config/audit-config.example.json`.

## 14. Boas práticas de utilização

- não guardar credenciais na configuração;
- manter os domínios apenas em `audit-config.json`;
- não alterar diretamente o perfil distribuído;
- utilizar uma diretoria de output distinta para cada auditoria relevante;
- rever manualmente os resultados `INCONCLUSIVE`;
- documentar todas as `PROFILE_EXCEPTION`;
- proteger os relatórios e evidências de acordo com a sensibilidade dos alvos;
- comparar Technical Debt, Compliance e Exposure entre execuções equivalentes;
- validar a configuração antes de iniciar scans demorados.
