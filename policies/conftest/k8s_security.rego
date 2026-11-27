package main

import rego.v1

pod_spec := input.spec if {
  input.kind == "Pod"
}

pod_spec := input.spec.template.spec if {
  input.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}
}

# 1. Wymuszenie runAsNonRoot: true
deny contains msg if {
  not pod_spec.securityContext.runAsNonRoot == true
  some c in pod_spec.containers
  not c.securityContext.runAsNonRoot == true
  msg := sprintf("[non-root] Kontener '%s' musi mieć ustawione runAsNonRoot: true.", [c.name])
}

# 2. Blokada privileged: true
deny contains msg if {
  some c in pod_spec.containers
  c.securityContext.privileged == true
  msg := sprintf("[privileged] Kontener '%s' używa zabronionego trybu privileged: true.", [c.name])
}

# 3a. Wymóg jawnego tagu obrazu
deny contains msg if {
  some c in pod_spec.containers
  not contains(c.image, ":")
  msg := sprintf("[image-tag] Obraz '%s' w kontenerze '%s' musi mieć podany tag wersji.", [c.image, c.name])
}

# 3b. Zakaz tagu :latest
deny contains msg if {
  some c in pod_spec.containers
  endswith(c.image, ":latest")
  msg := sprintf("[latest-tag] Obraz '%s' w kontenerze '%s' używa zabronionego tagu ':latest'.", [c.image, c.name])
}

# 4. Wymagane requests i limits dla CPU oraz RAM
deny contains msg if {
  some c in pod_spec.containers
  not has_resources(c)
  msg := sprintf("[resources] Kontener '%s' musi mieć zdefiniowane requests oraz limits dla CPU i pamięci.", [c.name])
}

has_resources(c) if {
  c.resources.requests.cpu
  c.resources.requests.memory
  c.resources.limits.cpu
  c.resources.limits.memory
}