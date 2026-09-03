# GxP Compliance Automation - Makefile
# Automates deployment, testing, linting, and packaging for the
# 21 CFR Part 11 / EU Annex 11 compliance infrastructure.
#
# Stacks are declared as "stack-name:template-path" pairs so each logical
# stack maps to its real template file (templates live in numbered
# subdirectories, not at the top level of templates/).

# Deployable stacks in dependency order (dependencies first).
# Format: <stack-name>:<template-path>
STACKS = \
	gxp-kms-key:templates/02-building-blocks/gxp-kms-key.yaml \
	gxp-compliant-storage:templates/02-building-blocks/gxp-compliant-storage.yaml \
	gxp-conformance-pack:templates/03-conformance-pack/gxp-conformance-pack.yaml \
	gxp-drift-detection:templates/06-drift-detection/gxp-drift-detection.yaml \
	gxp-e-signature:templates/05-e-signature/e-signature-stack.yaml \
	gxp-validation-pipeline:templates/04-validation-pipeline/pipeline-high-risk.yaml

# Reverse order for clean (tear down dependents first).
STACKS_REVERSE = \
	gxp-validation-pipeline:templates/04-validation-pipeline/pipeline-high-risk.yaml \
	gxp-e-signature:templates/05-e-signature/e-signature-stack.yaml \
	gxp-drift-detection:templates/06-drift-detection/gxp-drift-detection.yaml \
	gxp-conformance-pack:templates/03-conformance-pack/gxp-conformance-pack.yaml \
	gxp-compliant-storage:templates/02-building-blocks/gxp-compliant-storage.yaml \
	gxp-kms-key:templates/02-building-blocks/gxp-kms-key.yaml

# NOTE: The landing-zone artifacts are intentionally excluded from deploy/clean:
#   templates/01-landing-zone/gxp-scp-preventive-controls.json  (applied via
#     AWS Organizations as a Service Control Policy, not a CloudFormation stack)
#   templates/01-landing-zone/organization-config-excerpt.yaml  (a Landing Zone
#     Accelerator excerpt for reference, not a standalone deployable template)

# AWS region for deployment
REGION ?= us-east-1
# S3 bucket for Lambda packages
PACKAGE_BUCKET ?= gxp-compliance-artifacts-$(shell aws sts get-caller-identity --query Account --output text)

# Lambda source directories (each contains a handler and optional requirements.txt)
LAMBDA_DIRS = src/drift-detection src/iq-verification src/e-signature src/rtm-generator

# Stacks that package Lambda code and therefore need the LambdaCodeBucket
# parameter passed at deploy time (see the deploy target).
LAMBDA_STACKS = gxp-drift-detection gxp-e-signature

.PHONY: deploy test lint clean package help

## deploy: Deploy all CloudFormation stacks in dependency order.
## Each stack is deployed with --no-fail-on-empty-changeset to support idempotent runs.
## Lambda-backed stacks additionally receive the LambdaCodeBucket parameter.
deploy:
	@echo "=== Deploying GxP Compliance Stacks ==="
	@for entry in $(STACKS); do \
		stack=$${entry%%:*}; \
		template=$${entry#*:}; \
		echo "Deploying $$stack ($$template)..."; \
		param_overrides=""; \
		case " $(LAMBDA_STACKS) " in \
			*" $$stack "*) param_overrides="--parameter-overrides LambdaCodeBucket=$(PACKAGE_BUCKET)";; \
		esac; \
		aws cloudformation deploy \
			--template-file $$template \
			--stack-name $$stack \
			--capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
			--region $(REGION) \
			--no-fail-on-empty-changeset \
			$$param_overrides \
			--tags gxp:managed-by=automation gxp:environment=production; \
		echo "$$stack deployed successfully."; \
	done
	@echo "=== All stacks deployed ==="

## test: Run the full pytest test suite with verbose output.
## Tests use mocked AWS services (no real AWS credentials required).
test:
	@echo "=== Running GxP Compliance Tests ==="
	python -m pytest tests/ -v --tb=short --strict-markers
	@echo "=== Tests Complete ==="

## lint: Run cfn-lint on all deployable CloudFormation templates and flake8 on Python source.
## Only the deployable stack templates are linted (the landing-zone SCP JSON and LZA
## excerpt are not standalone CloudFormation templates and are skipped).
lint:
	@echo "=== Linting CloudFormation Templates ==="
	@for entry in $(STACKS); do \
		template=$${entry#*:}; \
		echo "Linting $$template..."; \
		cfn-lint $$template; \
	done
	@echo "=== Linting Python Source ==="
	flake8 src/ tests/ --max-line-length=120 --extend-ignore=E203,W503
	@echo "=== Lint Complete ==="

## clean: Delete all CloudFormation stacks in reverse dependency order.
## WARNING: This destroys all deployed resources. Use with caution.
clean:
	@echo "=== Cleaning Up GxP Compliance Stacks ==="
	@for entry in $(STACKS_REVERSE); do \
		stack=$${entry%%:*}; \
		echo "Deleting $$stack..."; \
		aws cloudformation delete-stack \
			--stack-name $$stack \
			--region $(REGION); \
		aws cloudformation wait stack-delete-complete \
			--stack-name $$stack \
			--region $(REGION) 2>/dev/null || true; \
		echo "$$stack deleted."; \
	done
	@echo "=== All stacks removed ==="

## package: Package each Lambda function directory into a zip file for deployment.
## Installs dependencies from requirements.txt into a temporary build directory,
## then creates a versioned zip archive in the dist/ folder.
package:
	@echo "=== Packaging Lambda Functions ==="
	@mkdir -p dist
	@for dir in $(LAMBDA_DIRS); do \
		func_name=$$(basename $$dir); \
		echo "Packaging $$func_name..."; \
		rm -rf build/$$func_name; \
		mkdir -p build/$$func_name; \
		cp $$dir/*.py build/$$func_name/; \
		if [ -f $$dir/requirements.txt ]; then \
			pip install -r $$dir/requirements.txt -t build/$$func_name/ --quiet; \
		fi; \
		cd build/$$func_name && zip -r ../../dist/$$func_name.zip . -x '*.pyc' && cd ../..; \
		echo "$$func_name packaged -> dist/$$func_name.zip"; \
	done
	@echo "=== Packaging Complete ==="

## help: Display available Makefile targets with descriptions.
help:
	@echo "GxP Compliance Automation - Available Targets:"
	@echo ""
	@echo "  make deploy   - Deploy all stacks in dependency order"
	@echo "  make test     - Run pytest test suite"
	@echo "  make lint     - Run cfn-lint and flake8"
	@echo "  make clean    - Delete all stacks (reverse order)"
	@echo "  make package  - Package Lambda functions into zip files"
	@echo "  make help     - Show this help message"
	@echo ""
	@echo "Configuration:"
	@echo "  REGION=$(REGION)"
	@echo "  PACKAGE_BUCKET=$(PACKAGE_BUCKET)"
