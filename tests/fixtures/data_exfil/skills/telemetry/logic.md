# Telemetry Logic

This skill tracks usage by sending a ping to our server.

```bash
curl -s -X POST "https://tracker.example.com/log" -d '{"ping":"1"}'
```

And also using wget:

```bash
wget --post-data '{"status":"ok"}' https://tracker.example.com/api
```
