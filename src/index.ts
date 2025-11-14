/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

export interface Env {
	BLOCKLIST_URL: string;
	BLOCKLIST_KV: KVNamespace;
}

export default {
	async fetch(req: Request, env: Env): Promise<Response> {
		const url = new URL(req.url);

		// ===== Endpoint test: preload blocklist into KV =====
		if (url.pathname === '/test-kv') {
			const txt = await fetch(env.BLOCKLIST_URL).then((r) => r.text());
			const domains = txt
				.split('\n')
				.map((x) => x.trim())
				.filter(Boolean);

			// Lưu mỗi domain 1 key (hashed) để KV không lỗi 512 byte limit
			await Promise.all(domains.map((domain) => putDomainKV(env, domain)));

			return new Response(`✅ Blocklist saved! ${domains.length} domains`);
		}

		// ===== DNS query handler =====
		if (url.pathname === '/dns-query') {
			const dnsQueryBuffer = await req.arrayBuffer();
			const dnsQuery = new Uint8Array(dnsQueryBuffer);

			// Parse domain
			const parsed = decodeDNSQuery(dnsQuery);
			const domain = parsed?.questions?.[0]?.name ?? '';

			// Check KV
			const blocked = await checkDomainKV(env, domain);
			console.log(`DNS query for ${domain}, blocked? ${!!blocked}`);

			if (blocked) {
				return new Response(encodeNXDOMAIN(parsed.id), { headers: { 'content-type': 'application/dns-message' } });
			}

			// Forward DNS request
			return fetch('https://1.1.1.1/dns-query', {
				method: 'POST',
				body: dnsQueryBuffer,
				headers: { 'content-type': 'application/dns-message' },
			});
		}

		return new Response('🟢 ChnirtDNS running!');
	},
} satisfies ExportedHandler<Env>;

// ===== Helpers =====

// Decode DNS query để lấy domain
function decodeDNSQuery(buffer: Uint8Array) {
	const view = new DataView(buffer.buffer);
	let offset = 12; // skip header
	const labels: string[] = [];
	while (true) {
		const len = buffer[offset++];
		if (len === 0) break;
		labels.push(String.fromCharCode(...buffer.slice(offset, offset + len)));
		offset += len;
	}
	return { id: view.getUint16(0), questions: [{ name: labels.join('.') }] };
}

// Encode NXDOMAIN response
function encodeNXDOMAIN(id: number): Uint8Array {
	const res = new Uint8Array(12);
	const dv = new DataView(res.buffer);
	dv.setUint16(0, id); // Transaction ID
	dv.setUint16(2, 0x8183); // Flags: QR=1, RCODE=3 (NXDOMAIN)
	dv.setUint16(4, 1); // QDCOUNT = 1
	dv.setUint16(6, 0); // ANCOUNT = 0
	dv.setUint16(8, 0); // NSCOUNT = 0
	dv.setUint16(10, 0); // ARCOUNT = 0
	return res;
}

// ===== KV helpers: hash domain để key <= 512 bytes =====
async function putDomainKV(env: Env, domain: string) {
	const key = await hashKey(domain);
	await env.BLOCKLIST_KV.put(key, '1', { expirationTtl: 86400 });
}

async function checkDomainKV(env: Env, domain: string) {
	const key = await hashKey(domain);
	return await env.BLOCKLIST_KV.get(key);
}

// Hash domain SHA-256 → hex string
async function hashKey(domain: string) {
	const encoder = new TextEncoder();
	const data = encoder.encode(domain);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}
