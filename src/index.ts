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
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		// Endpoint DNS-over-HTTPS
		if (url.pathname === '/dns-query') {
			const dnsQueryBuffer = await request.arrayBuffer();
			const dnsQuery = new Uint8Array(dnsQueryBuffer);

			// Lấy blocklist từ Supabase
			const blockText = await fetch(env.BLOCKLIST_URL).then((r) => r.text());
			const blocklist = new Set(
				blockText
					.split('\n')
					.map((x) => x.trim())
					.filter(Boolean)
			);

			// Decode DNS message
			const parsed = decodeDNSQuery(dnsQuery);
			const domain = parsed?.questions?.[0]?.name ?? '';

			// Nếu domain bị chặn → trả NXDOMAIN
			if (blocklist.has(domain)) {
				return new Response(encodeNXDOMAIN(parsed.id), {
					headers: { 'content-type': 'application/dns-message' },
				});
			}

			// Forward sang Cloudflare 1.1.1.1 DNS
			return fetch('https://1.1.1.1/dns-query', {
				method: 'POST',
				body: dnsQueryBuffer,
				headers: { 'content-type': 'application/dns-message' },
			});
		}

		// Ping test
		return new Response('ChnirtDNS is running!');
	},
} satisfies ExportedHandler<Env>;

// ===== Helper functions =====

function decodeDNSQuery(buffer: Uint8Array) {
	const view = new DataView(buffer.buffer);
	let offset = 12;
	const labels: string[] = [];

	while (true) {
		const len = buffer[offset++];
		if (len === 0) break;
		labels.push(String.fromCharCode(...buffer.slice(offset, offset + len)));
		offset += len;
	}

	return {
		id: view.getUint16(0),
		questions: [{ name: labels.join('.') }],
	};
}

function encodeNXDOMAIN(id: number): Uint8Array {
	const res = new Uint8Array(12);
	const dv = new DataView(res.buffer);
	dv.setUint16(0, id); // request ID
	dv.setUint16(2, 0x8183); // flags: response + NXDOMAIN
	return res;
}
