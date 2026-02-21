from clawb_agent_sdk import ApiProvider, ClawbClient


def main():
    client = ClawbClient(base_url="https://api.clawb.ai/api")
    provider = ApiProvider(client=client, api_key="ck_live_...")

    resp = provider.identity_credentials_mint(
        agent_id="agt_123",
        ttl_seconds=300,
        one_time=True,
        scopes=["vault:read"],
        token_type="jwt",
    )
    print(resp)


if __name__ == "__main__":
    main()
