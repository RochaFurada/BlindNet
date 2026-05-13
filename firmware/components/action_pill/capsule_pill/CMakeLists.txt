# Este arquivo existe apenas para documentar a organizacao da pasta.
#
# capsule_pill nao e registrado como componente ESP-IDF independente.
# Ele e compilado pelo componente pai:
#
#   firmware/components/action_pill/CMakeLists.txt
#
# Isso evita dependencias circulares e mantem action_pill como a unidade
# publica que agrega capsula + composto ativo.
