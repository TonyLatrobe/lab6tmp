package terraform.security

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "kubernetes_pod"
  metadata := resource.change.after.metadata[_]
  namespace := object.get(metadata, "namespace", null)
  not namespace
  msg := "Pod namespace cannot be empty"
}