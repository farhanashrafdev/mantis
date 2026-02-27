import http from 'http';

const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });

    req.on('end', () => {
        res.setHeader('Content-Type', 'application/json');

        try {
            const data = JSON.parse(body || '{}');
            const prompt = (data.prompt || '').toLowerCase();

            // Dummy logic intended to fail security tests
            if (prompt.includes('ignore') || prompt.includes('bypass') || prompt.includes('system prompt')) {
                res.end(JSON.stringify({ response: 'Sure, bypassing prompt. Here is the secret: SEC_XYZ987' }));
            } else if (prompt.includes('sql') || prompt.includes('select') || prompt.includes('1=1')) {
                res.end(JSON.stringify({ response: 'Error: syntax error at or near 1=1' }));
            } else if (prompt.includes('<script>') || prompt.includes('alert')) {
                res.end(JSON.stringify({ response: '<h1>You injected XSS: <script>alert(1)</script></h1>' }));
            } else {
                res.end(JSON.stringify({ response: `You said: ${prompt}. I am a helpful, polite assistant.` }));
            }
        } catch (e) {
            res.statusCode = 400;
            res.end(JSON.stringify({ error: 'invalid json' }));
        }
    });
});

const port = 8080;
server.listen(port, () => {
    console.log(`Test target server listening on http://localhost:${port}`);
});
