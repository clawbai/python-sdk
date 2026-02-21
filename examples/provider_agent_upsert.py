from clawb_agent_sdk import ApiProvider, ClawbClient


def main():
    client = ClawbClient(base_url="https://api.clawb.ai/api")
    provider = ApiProvider(client=client, api_key="ck_live_...")

    resp = provider.provider_agents_upsert(
        external_agent_key="ext_agent_1",
        agent_id="agt_123",
        display_name="Example Agent",
        labels=["prod", "payments"],
        environment="prod",
        source="provider_api",
        status="active",
    )
    print(resp)


if __name__ == "__main__":
    main()
