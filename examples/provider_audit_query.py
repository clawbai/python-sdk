from clawb_agent_sdk import ApiProvider, ClawbClient


def main():
    client = ClawbClient(base_url="https://api.clawb.ai/api")
    provider = ApiProvider(client=client, api_key="ck_live_...")

    resp = provider.provider_audit_events(
        start_ms=0,
        end_ms=None,
        agent_id="agt_123",
        limit=25,
    )
    print(resp)


if __name__ == "__main__":
    main()
