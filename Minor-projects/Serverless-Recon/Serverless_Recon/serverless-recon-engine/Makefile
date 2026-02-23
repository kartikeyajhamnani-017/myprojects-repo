.PHONY: deploy-infra deploy-func clean

deploy-infra:
	cd infra && terraform apply

deploy-func:
	cd src/function && gcloud functions deploy recon-engine \
		--gen2 \
		--runtime go121 \
		--entry-point HandlePubSub \
		--trigger-topic recon-topic \
		--region us-central1

clean:
	rm -f src/function/function