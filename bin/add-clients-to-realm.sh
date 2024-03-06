#!/bin/bash

prometheus_client=$(<data/import-clients/prometheus-cilent.json)
grafana_client=$(<data/import-clients/grafana-client.json)

cat data/import/dcm4che-realm.json \
  | jq --argjson insert "${grafana_client}" '.clients += [$insert]' \
  | jq --argjson insert "${}prometheus_client}" '.clients += [$insert]' \
  > data/import/dcm4chee-realm-pro.json

rm data/import/dcm4che-realm.json