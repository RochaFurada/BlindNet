# Este arquivo existe apenas para documentar a organizacao da pasta.
#
# active_substance nao e registrado como componente ESP-IDF independente.
# Ele e compilado pelo componente pai:
#
#   firmware/components/action_pill/CMakeLists.txt
#
# Isso deixa o composto ativo como submodulo interno do action_pill,
# junto com capsule_pill.
