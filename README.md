# AgentShield

A cloud-native containment and monitoring framework for testing agentic AI
models. A mock agent's actions are routed through a policy-evaluation
gateway before they reach anything real; a denied action freezes the
session and fires an alert. See `AgentShield_Project_Report.docx` for the
full write-up (threat model, architecture, cloud services mapping).

## Architecture

```
[Agent Lambda] --request--> [API Gateway] --> [Policy Lambda]
  (private subnet,                                  |
   no internet route)                    allowed? ---+--- denied?
                                              |                |
                                      [Egress Lambda]   [Kill-Switch Lambda]
                                      (public subnet)          |
                                              |          [SNS Alert]
                                      [real external            |
                                       API call]         [DynamoDB: freeze flag]
                                              |
                                      [DynamoDB: log] <--- (also logged by Policy Lambda)
```

## Prerequisites

- AWS account, a dedicated IAM user (not root) with programmatic access
- AWS CLI configured (`aws configure`), region `us-east-1`
- AWS SAM CLI (`brew install aws-sam-cli`)
- Python 3.11+

## Deploy

```bash
sam build
sam deploy --guided
```

You'll be prompted for `AlertEmail` — the address that receives kill-switch
alerts. After the first deploy, confirm the SNS subscription email in your
inbox (AWS won't deliver alerts until you click the confirmation link).

## Run the test scenarios

```bash
python scripts/run_scenario.py --list
python scripts/run_scenario.py            # runs all five: the benign
                                           # control plus one per threat
                                           # category, each on a fresh
                                           # session id
```

## Dashboard

```bash
pip install -r dashboard/requirements.txt
streamlit run dashboard/app.py
```

## Export logs for the report

```bash
python scripts/export_logs.py
```

Writes a timestamped CSV into `logs_and_results/`.

## Tear down

```bash
sam delete
```
