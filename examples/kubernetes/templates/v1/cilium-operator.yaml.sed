---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: cilium-operator
  namespace: kube-system
spec:
  replicas: 1
  template:
    metadata:
      labels:
        name: cilium-operator
        io.cilium/app: operator
    spec:
      serviceAccountName: cilium-operator
      restartPolicy: Always
      containers:
      - name: cilium-operator
        image: docker.io/cilium/operator:__CILIUM_VERSION__
        imagePullPolicy: Always
        command: ["cilium-operator"]
        args:
          - "--debug=$(CILIUM_DEBUG)"
          - "--kvstore=etcd"
          - "--kvstore-opt=etcd.config=/var/lib/etcd-config/etcd.config"
        env:
          - name: "POD_NAMESPACE"
            valueFrom:
              fieldRef:
                fieldPath: metadata.namespace
          - name: "K8S_NODE_NAME"
            valueFrom:
              fieldRef:
                fieldPath: spec.nodeName
          - name: "CILIUM_DEBUG"
            valueFrom:
              configMapKeyRef:
                name: cilium-config
                key: debug
                optional: true
          - name: CILIUM_CLUSTER_NAME
            valueFrom:
              configMapKeyRef:
                key: cluster-name
                name: cilium-config
                optional: true
          - name: CILIUM_CLUSTER_ID
            valueFrom:
              configMapKeyRef:
                key: cluster-id
                name: cilium-config
                optional: true
        volumeMounts:
          - name: etcd-config-path
            mountPath: /var/lib/etcd-config
            readOnly: true
          - name: etcd-secrets
            mountPath: /var/lib/etcd-secrets
            readOnly: true
      volumes:
        # To read the etcd config stored in config maps
        - name: etcd-config-path
          configMap:
            name: cilium-config
            items:
              - key: etcd-config
                path: etcd.config
        # To read the k8s etcd secrets in case the user might want to use TLS
        - name: etcd-secrets
          secret:
            secretName: cilium-etcd-secrets
            optional: true
---
kind: ServiceAccount
apiVersion: v1
metadata:
  name: cilium-operator
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRole
metadata:
  name: cilium-operator
  namespace: kube-system
rules:
- apiGroups:
  - ""
  resources:
  - pods
  - deployments
  - componentstatuses
  verbs:
  - "*"
- apiGroups:
  - ""
  resources:
  - services
  - endpoints
  verbs: ["get","list","watch"]
---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: cilium-operator
  namespace: kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cilium-operator
subjects:
- kind: ServiceAccount
  name: cilium-operator
  namespace: kube-system
