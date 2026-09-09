# Manual de Gestão do Repositório GitHub

## Web Security Audit

Este manual documenta o processo recomendado para criar, manter, versionar, publicar e recuperar o repositório GitHub do projeto **Web Security Audit**.

O objetivo é garantir um processo simples, repetível e seguro para futuras versões, mesmo que a máquina local ou a cópia do OneDrive deixem de estar disponíveis.

---

## 1. Estrutura recomendada do repositório

```text
web-security-audit/
├── src/
│   ├── web-security-audit.py
│   └── componentes internos do motor
├── profiles/
│   └── profile-web-security-external.json
├── config/
│   └── audit-config.example.json
├── docs/
│   ├── MANUAL.md
│	├── MANUAL-GITHUB.md
│   └── CHANGELOG.md
├── releases/
├── install.sh
├── README.md
└── .gitignore
└── .gitattributes
```

### Recomendações

- Manter em `src/` apenas o código-fonte necessário para a versão atual.
- Manter em `profiles/` os perfis normativos distribuídos com o projeto.
- Manter em `config/` apenas configurações de exemplo, sem domínios privados, credenciais ou dados operacionais.
- Manter em `docs/` a documentação funcional, técnica e o histórico de alterações.
- Não versionar relatórios, evidências, certificados extraídos ou resultados temporários.

---

## 2. Criar o repositório no GitHub

No GitHub:

1. Selecionar **New repository**.
2. Definir o nome:

```text
web-security-audit
```

3. Escolher a visibilidade adequada. Para um projeto que contém perfis ou controlos internos, utilizar normalmente:

```text
Private
```

4. Criar o repositório.

> Se os ficheiros já existem localmente, não é necessário pedir ao GitHub para criar automaticamente README, `.gitignore` ou licença.

---

## 3. Inicializar o repositório local

Entrar na pasta do projeto:

```bash
cd web-security-audit
```

Inicializar o Git:

```bash
git init
```

Verificar o estado inicial:

```bash
git status
```

Adicionar os ficheiros:

```bash
git add .
```

Criar o primeiro commit:

```bash
git commit -m "Initial release v12.4"
```

Definir `main` como branch principal:

```bash
git branch -M main
```

Associar o repositório local ao GitHub:

```bash
git remote add origin https://github.com/<utilizador>/web-security-audit.git
```

Publicar a branch principal:

```bash
git push -u origin main
```

Substituir `<utilizador>` pelo utilizador ou organização onde o repositório foi criado.

---

## 4. Confirmar a configuração do repositório

Verificar o estado:

```bash
git status
```

Confirmar o repositório remoto:

```bash
git remote -v
```

Consultar o histórico resumido:

```bash
git log --oneline --decorate --graph
```

Consultar as tags existentes:

```bash
git tag --list
```

---

## 5. Configurar o `.gitignore`

Criar o ficheiro `.gitignore` na raiz do repositório:

```gitignore
# Resultados e evidências
reports/
details/

# Artefactos produzidos pelo auditor
WEB_SECURITY_AUDIT*.html
audit-results.json
executive-summary.csv

# Ficheiros potencialmente sensíveis
*.pem
*.key
*.crt

# Logs e ficheiros temporários
*.log
.audit/
.tmp/

# Python
__pycache__/
*.pyc
*.pyo

# Ambientes virtuais
.venv/
venv/

# Ficheiros locais de configuração
config/audit-config.json
audit-config.json

# Sistema operativo e editores
.DS_Store
Thumbs.db
.vscode/
.idea/
```

### Nota sobre configurações

Versionar apenas:

```text
config/audit-config.example.json
```

Não versionar o `audit-config.json` operacional caso contenha domínios internos ou exceções específicas.

Confirmar o que será incluído no próximo commit:

```bash
git status
```

---

## 6. Fluxo diário de trabalho

Antes de começar alterações:

```bash
git switch main
git pull --ff-only
```

Consultar o estado:

```bash
git status
```

Depois de alterar ficheiros, rever as diferenças:

```bash
git diff
```

Adicionar alterações específicas:

```bash
git add src/ profiles/ config/ docs/ README.md
```

Ou adicionar todas as alterações intencionais:

```bash
git add .
```

Criar o commit:

```bash
git commit -m "Improve TLS audit reporting"
```

Publicar:

```bash
git push
```

---

## 7. Trabalhar numa nova funcionalidade

Para alterações que ainda não devem entrar diretamente em `main`, criar uma branch:

```bash
git switch -c feature/nome-da-alteracao
```

Exemplo:

```bash
git switch -c feature/http-security-headers
```

Efetuar alterações e testes. Depois:

```bash
git add .
git commit -m "Add HTTP security header validation"
git push -u origin feature/http-security-headers
```

Após validação, integrar a branch através de um Pull Request no GitHub ou localmente:

```bash
git switch main
git pull --ff-only
git merge --no-ff feature/http-security-headers
git push
```

Remover a branch local após integração:

```bash
git branch -d feature/http-security-headers
```

---

## 8. Preparar uma nova versão

Antes de criar uma release:

1. Atualizar a versão apresentada pelo programa.
2. Executar os testes funcionais.
3. Validar o perfil predefinido.
4. Atualizar `audit-config.example.json`.
5. Atualizar `README.md`.
6. Atualizar `docs/MANUAL.md`.
7. Atualizar `docs/CHANGELOG.md`.
8. Gerar o pacote autónomo.
9. Verificar os checksums.

Exemplo para a versão `v12.5`:

```bash
git add .
git commit -m "Release v12.5"
```

Criar uma tag anotada:

```bash
git tag -a v12.5 -m "Web Security Audit v12.5"
```

Publicar o commit:

```bash
git push origin main
```

Publicar a tag:

```bash
git push origin v12.5
```

Confirmar:

```bash
git tag --list
git show v12.5
```

---

## 9. Criar uma Release no GitHub

No GitHub:

1. Abrir o repositório.
2. Selecionar **Releases**.
3. Selecionar **Create a new release**.
4. Escolher a tag, por exemplo:

```text
v12.5
```

5. Definir o título:

```text
Web Security Audit v12.5
```

6. Incluir um resumo das alterações com base no `CHANGELOG.md`.
7. Anexar o pacote autónomo:

```text
web-security-audit-v12.5-autonomous.zip
```

8. Anexar o respetivo checksum:

```text
web-security-audit-v12.5-autonomous.zip.sha256
```

9. Publicar a release.

---

## 10. Manter o `CHANGELOG.md`

Estrutura recomendada:

```markdown
# Changelog

## 12.5.0

### Added

- Novo controlo de segurança.
- Nova exportação executiva.

### Changed

- Melhoria da classificação TLS.
- Atualização do relatório HTML.

### Fixed

- Correção da allowlist de cifras.
- Eliminação de penalizações duplicadas.
```

Atualizar o changelog antes de criar a tag da versão.

---

## 11. Manter uma única versão corrente do código

Em vez de acumular ficheiros como:

```text
web-security-audit-v12.4.py
web-security-audit-v12.5.py
web-security-audit-v12.6.py
```

utilizar preferencialmente um nome estável:

```text
src/web-security-audit.py
```

A identificação das versões deve ser feita através de:

- número de versão dentro do programa;
- commits;
- tags Git;
- releases GitHub.

Para manter compatibilidade com os pacotes existentes, a mudança de nome pode ser feita numa versão futura planeada.

---

## 12. Clonar o repositório noutro computador

```bash
git clone https://github.com/<utilizador>/web-security-audit.git
```

Entrar na pasta:

```bash
cd web-security-audit
```

Verificar as versões:

```bash
git tag --list
```

Instalar ou validar conforme o manual do projeto:

```bash
./install.sh
```

---

## 13. Recuperar uma versão antiga

Consultar as tags:

```bash
git tag --list
```

Consultar uma versão sem alterar ficheiros:

```bash
git show v12.4
```

Mudar temporariamente para uma tag:

```bash
git switch --detach v12.4
```

Voltar à branch principal:

```bash
git switch main
```

Para criar uma branch baseada numa versão antiga:

```bash
git switch -c hotfix/v12.4.1 v12.4
```

---

## 14. Corrigir o último commit local

Se o commit ainda não foi publicado:

```bash
git add .
git commit --amend
```

Para alterar apenas a mensagem:

```bash
git commit --amend -m "Mensagem corrigida"
```

Evitar reescrever commits que já foram partilhados com outras pessoas, salvo se o processo da equipa permitir explicitamente essa operação.

---

## 15. Anular alterações locais

Ver alterações:

```bash
git status
git diff
```

Repor um ficheiro ainda não adicionado ao stage:

```bash
git restore caminho/do/ficheiro
```

Remover um ficheiro do stage, mantendo as alterações:

```bash
git restore --staged caminho/do/ficheiro
```

Não usar comandos destrutivos como `git reset --hard` sem confirmar previamente o impacto.

---

## 16. Criar um backup completo do repositório

Criar um Git bundle com branches e tags:

```bash
git bundle create web-security-audit.bundle --all
```

Validar o bundle:

```bash
git bundle verify web-security-audit.bundle
```

Restaurar noutro local:

```bash
git clone web-security-audit.bundle web-security-audit-restored
```

O bundle preserva o histórico Git, branches e tags incluídas no momento da criação.

---

## 17. Verificações de segurança antes de publicar

Antes de cada `git push`, procurar dados que não devem ser publicados:

```bash
git diff --cached
```

Confirmar que não são incluídos:

- credenciais;
- tokens;
- chaves privadas;
- certificados privados;
- configurações internas não autorizadas;
- relatórios com dados sensíveis;
- domínios ou endereços internos sem aprovação;
- evidências produzidas pelas auditorias.

Se um segredo for publicado, remover o segredo do sistema de origem e proceder à respetiva rotação. Apagar apenas o ficheiro do commit seguinte não elimina o segredo do histórico anterior.

---

## 18. Checklist antes de um commit

```text
[ ] git status revisto
[ ] git diff revisto
[ ] Apenas ficheiros intencionais adicionados
[ ] Sem credenciais ou dados sensíveis
[ ] Código testado
[ ] Configuração de exemplo validada
[ ] Perfil validado
[ ] Documentação atualizada quando aplicável
[ ] Mensagem de commit clara
```

---

## 19. Checklist antes de uma release

```text
[ ] Branch main atualizada
[ ] Código testado
[ ] Testes executados
[ ] Testes adicionais executados quando aplicável
[ ] Perfil predefinido validado
[ ] audit-config.example.json atualizado
[ ] README.md atualizado
[ ] MANUAL.md atualizado
[ ] CHANGELOG.md atualizado
[ ] Pacote autónomo gerado
[ ] Checksums gerados e verificados
[ ] Commit da release criado
[ ] Tag anotada criada
[ ] Branch main publicada
[ ] Tag publicada
[ ] Release criada no GitHub
[ ] ZIP e checksum anexados à release
```

---

## 20. Sequência rápida para futuras releases

Substituir `12.5` pela versão pretendida:

```bash
git switch main
git pull --ff-only
git status

# Atualizar código, perfis e documentação

./install.sh

# Executar testes funcionais necessários

git diff
git add .
git commit -m "Release v12.5"
git tag -a v12.5 -m "Web Security Audit v12.5"
git push origin main
git push origin v12.5
```

Depois criar a release no GitHub e anexar:

```text
web-security-audit-v12.5-autonomous.zip
web-security-audit-v12.5-autonomous.zip.sha256
```

---

## 21. Comandos de referência rápida

```bash
# Estado
git status

# Diferenças ainda não adicionadas
git diff

# Diferenças preparadas para commit
git diff --cached

# Histórico
git log --oneline --decorate --graph

# Atualizar repositório local
git pull --ff-only

# Publicar alterações
git add .
git commit -m "Descrição da alteração"
git push

# Criar e publicar tag
git tag -a v12.5 -m "Web Security Audit v12.5"
git push origin v12.5

# Ver remotos
git remote -v

# Ver tags
git tag --list
```

---

## Regra operacional principal

Antes de cada alteração:

```text
Pull → Alterar → Testar → Rever → Commit → Push
```

Antes de cada release:

```text
Testar → Documentar → Empacotar → Verificar → Commit → Tag → Push → Release
```

## 18. Construção automatizada da distribuição

A criação dos artefactos de uma release deve ser feita exclusivamente através de `build-release.sh`. O script lê a versão diretamente de `web-security-audit.py`:

```python
V='1.0.2'
VERSION=V
```

O processo de build deve:

1. validar que os ficheiros obrigatórios existem;
2. recriar a diretoria temporária `dist/`;
3. montar a árvore `web-security-audit-<versão>/`;
4. excluir caches, bytecode, configurações operacionais, relatórios e evidências;
5. produzir `SHA256SUMS.txt` para os ficheiros internos;
6. criar o ZIP em `dist/`;
7. copiar o ZIP para `releases/`;
8. gerar o checksum do ZIP dentro de `releases/`;
9. validar o checksum a partir de `releases/`;
10. testar a extração e a estrutura do pacote num diretório temporário limpo.

Execução:

```bash
chmod 750 build-release.sh
./build-release.sh
```

Resultado esperado:

```text
dist/
├── web-security-audit-1.0.2/
└── web-security-audit-1.0.2.zip

releases/
├── web-security-audit-1.0.2.zip
└── web-security-audit-1.0.2.zip.sha256
```

`dist/` é uma área temporária e reconstruível. `releases/` é o arquivo local dos artefactos prontos para anexar à GitHub Release.

## 19. Estrutura obrigatória do ZIP

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

O ZIP não deve conter:

```text
.git/
.github/
dist/
releases/
reports/
audit-output/
details/
__pycache__/
*.pyc
audit-config.json
WEB_SECURITY_AUDIT*.html
audit-results.json
executive-summary.csv
MANUAL-GITHUB.md
```

## 20. Validação do instalador dentro da distribuição

A compilação do motor no repositório não valida os caminhos do pacote. Antes de publicar, o `install.sh` deve ser executado a partir de um ZIP extraído num diretório limpo:

```bash
TEST_DIR="$(mktemp -d)"
cp releases/web-security-audit-1.0.2.zip "$TEST_DIR/"

(
  cd "$TEST_DIR"
  unzip -q web-security-audit-1.0.2.zip
  cd web-security-audit-1.0.2
  ./install.sh
)

rm -rf "$TEST_DIR"
```

O instalador distribuído deve usar estes caminhos:

```text
config/audit-config.example.json
profiles/profile-web-security-external.json
```

A configuração de trabalho deve ser criada na raiz extraída como `audit-config.json`, sem substituir um ficheiro já existente.

## 21. Checksums internos e checksum da release

O ficheiro interno:

```text
web-security-audit-1.0.2/SHA256SUMS.txt
```

protege os ficheiros incluídos no pacote.

O ficheiro externo:

```text
releases/web-security-audit-1.0.2.zip.sha256
```

protege o ZIP publicado.

O checksum externo deve ser gerado e validado no mesmo diretório do ZIP:

```bash
(
  cd releases
  sha256sum web-security-audit-1.0.2.zip \
    > web-security-audit-1.0.2.zip.sha256
  sha256sum -c web-security-audit-1.0.2.zip.sha256
)
```

Resultado esperado:

```text
web-security-audit-1.0.2.zip: OK
```

## 22. Finais de linha para scripts Linux

Os scripts shell devem ser distribuídos com finais de linha LF. Para impedir que Git ou editores Windows introduzam CRLF, manter na raiz:

```gitattributes
*.sh text eol=lf
*.py text eol=lf
*.json text eol=lf
*.md text eol=lf
```

Depois de criar ou alterar `.gitattributes`:

```bash
git add --renormalize .
git status
git diff --cached
```

Verificação local:

```bash
find . -type f \
  \( -name "*.sh" -o -name "*.py" \) \
  -exec file {} \;
```

Se um script já tiver CRLF:

```bash
sed -i 's/\r$//' build-release.sh install.sh
```

## 23. Publicação dos artefactos

Os dois assets oficiais da release são:

```text
releases/web-security-audit-1.0.2.zip
releases/web-security-audit-1.0.2.zip.sha256
```

O código-fonte permanece no histórico Git. Os artefactos ZIP são distribuídos através da GitHub Release. Se `releases/` for apenas um arquivo local, deve constar de `.gitignore`:

```gitignore
releases/
```

Antes do upload, confirmar:

```bash
unzip -l releases/web-security-audit-1.0.2.zip

(
  cd releases
  sha256sum -c web-security-audit-1.0.2.zip.sha256
)
```

## 24. Separação entre documentação de utilizador e documentação de desenvolvimento

- `docs/MANUAL.md` contém apenas instalação, configuração, execução, interpretação de resultados e resolução de problemas do ponto de vista do utilizador.
- `docs/MANUAL-GITHUB.md` contém organização do repositório, branches, build, empacotamento, checksums, tags, publicação e manutenção das releases.
- `README.md` fornece início rápido e ligações para os dois manuais.
- `docs/CHANGELOG.md` regista alterações por versão.

Antes de uma release, rever o manual de utilizador para garantir que não contém instruções de Git, GitHub, branches, tags, `.gitignore`, `.gitattributes`, `dist/`, `releases/` ou construção de pacotes.
