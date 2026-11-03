package compliance.pci_dss

# Resolve effective runAsNonRoot from the container's explicit setting, or
# inherit it from the pod-level securityContext if the container does not set it.
container_runs_nonroot(pod, container) {
    container_sc := object.get(container, "securityContext", {})
    object.get(container_sc, "runAsNonRoot", null) == true
}

container_runs_nonroot(pod, container) {
    container_sc := object.get(container, "securityContext", {})
    object.get(container_sc, "runAsNonRoot", null) == null
    pod_sc := object.get(pod, "securityContext", {})
    object.get(pod_sc, "runAsNonRoot", false) == true
}

violation[msg] {
    input.kind == "Deployment"
    pod := input.spec.template.spec
    container := pod.containers[_]
    not container_runs_nonroot(pod, container)
    msg := sprintf("PCI-DSS 2.2: container '%v' must run as non-root (container or inherited pod context).", [container.name])
}

violation[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    container_sc := object.get(container, "securityContext", {})
    object.get(container_sc, "privileged", false) == true
    msg := sprintf("PCI-DSS 2.2: container '%v' cannot run privileged.", [container.name])
}

# Check the configured encryption algorithm when a Terraform plan includes an
# aws_s3_bucket_server_side_encryption_configuration resource.
# This is not a proof that all buckets have encryption resources or are compliant.
violation[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    rule := resource.change.after.rule[_]
    object.get(object.get(rule, "apply_server_side_encryption_by_default", {}), "sse_algorithm", "") != "aws:kms"
    msg := sprintf("PCI-DSS 3.4: resource '%v' must use aws:kms encryption.", [resource.address])
}
