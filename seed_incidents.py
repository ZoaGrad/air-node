import httpx
import asyncio

async def main():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as c:
        print("Registering workflow...")
        r = await c.post("/workflow", json={"name": "test-wf", "definition": {"START": ["END"]}})
        wid = r.json()["workflow_id"]
        
        print("Registering agent and session...")
        await c.post("/agent", json={"id": "agt-x", "name": "Agent X"})
        await c.post("/session", json={"id": "ses-x", "agent_id": "agt-x", "workflow_id": wid})
        
        print("Firing exactly 20 incidents to target 0.08 variance (INTERDICT_DRIFT)...")
        for i in range(20):
            # Unauthorized state transition (START -> BOGUS)
            await c.post("/event", json={
                "agent_id": "agt-x", 
                "session_id": "ses-x", 
                "action": f"hack_{i}", 
                "state_before": "START", 
                "state_after": "BOGUS"
            })
            await asyncio.sleep(0.5)
            
        print("Complete.")

if __name__ == "__main__":
    asyncio.run(main())
