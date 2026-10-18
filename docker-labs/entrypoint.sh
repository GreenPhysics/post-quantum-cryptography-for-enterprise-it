#!/usr/bin/env bash
# Container entrypoint: run every self-contained lab once, build the report,
# serve it. Auto-run happens at start; results reflect THIS machine, now.
set -u
echo "== PQC Lab Companion =="
openssl version
bash  /opt/pqc/docker-labs/run-labs.sh /opt/pqc/labs /opt/pqc/results
python3 /opt/pqc/docker-labs/make-report.py /opt/pqc/results /opt/pqc/www/index.html
echo "== report ready: http://localhost:8080 =="
cd /opt/pqc/www && exec python3 -m http.server 8080
