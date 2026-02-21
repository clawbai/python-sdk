from clawb_agent_sdk import ApiProvider, ClawbClient


def main():
    client = ClawbClient(base_url="https://api.clawb.ai/api")
    provider = ApiProvider(client=client, api_key="ck_live_...")

    resp = provider.reputation_feedback(
        agent_id="agt_123",
        verdict="ok",
        evidence={"source": "example", "note": "agent behaved normally"},
    )
    print(resp)


if __name__ == "__main__":
    main()
