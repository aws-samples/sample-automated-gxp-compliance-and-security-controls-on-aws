# GxP Compliance Automation - Makefile
# Automates deployment, testing, linting, and packaging for the
# 21 CFR Part 11 / EU Annex 11 compliance infrastructure.

# Stack names in deployment order (dependencies first)
STACKS = gxp-foundation gxp-audit-trail gxp-drift-detection gxp-iq-verification gxp-e-signature
# Reverse order for clean (tear down dependents first)
STACKS_REVERSE = gxp-e-signature gxp-iq-verification gxp-drift-detection gxp-audit-trail gxp-foundation

# AWS region for deployment
REGION ?= us-east-1
# S3 bucket for Lambda packages
PACKAGE_BUCKET ?= gxp-compliance-artifacts-$(shell aws sts get-caller-identity --query Account --output text)

# Lambda source directories
LAMBDA_DIRS = src/drift-detection src/iq-verification src/e-signature src/audit-trail

.PHONY: deploy test lint clean package help

## deploy: Deploy all CloudFormation stacks in dependency order.
## Each stack is deployed with --no-fail-on-empty-changeset to support idempotent runs.
deploy:
	@echo "=== Deploying GxP Compliance Stacks ==="
	@for stack in $(STACKS); do \
		echo "Deploying $$stack..."; \
		aws cloudformation deploy \
			--template-file templates/$$stack.yaml \
			--stack-name $$stack \
			--capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
			--region $(REGION) \
			--no-fail-on-empty-changeset \
			--tags gxp:managed-by=automation gxp:environment=production; \
		echo "$$stack deployed successfully."; \
	done
	@echo "=== All stacks deployed ==="

## test: Run the full pytest test suite with verbose output and coverage report.
## Tests use mocked AWS services (no real AWS credentials required).
test:
	@echo "=== Running GxP Compliance Tests ==="
	python -m pytest tests/ -v --tb=short --strict-markers
	@echo "=== Tests Complete ==="

## lint: Run cfn-lint on all CloudFormation templates and flake8 on Python source.
## Ensures IaC templates are valid and Python code follows style guidelines.
lint:
	@echo "=== Linting CloudFormation Templates ==="
	cfn-lint templates/*.yaml
	@echo "=== Linting Python Source ==="
	flake8 src/ tests/ --max-line-length=120 --extend-ignore=E203,W503
	@echo "=== Lint Complete ==="

## clean: Delete all CloudFormation stacks in reverse dependency order.
## WARNING: This destroys all deployed resources. Use with caution.
clean:
	@echo "=== Cleaning Up GxP Compliance Stacks ==="
	@for stack in $(STACKS_REVERSE); do \
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
