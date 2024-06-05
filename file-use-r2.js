// curl -X PUT -T ${uploadfile} -H "X-Custom-Auth-Key: ${key}" https://your.workers.domain/path
// curl -X DELETE -H "X-Custom-Auth-Key: ${key}" https://your.workers.domain/path

/**
 * @typedef {object} Env
 * @property {R2Bucket} FILE
 * @property {string} AUTH_KEY_SECRET - you need set X-Custom-Auth-Key in env
 */

export default {
    /**
     * @param {Request} request
     * @param {Env} env
     * @param {ExecutionContext} ctx
     * @returns {Promise<Response>}
     */
    async fetch(request, env, ctx) {
        const { hostname, pathname } = new URL(request.url);
        const key = hostname + pathname;

        switch (request.method) {
            case 'PUT':
                if (!hasValidHeader(request, env)) {
                    return new Response('no permission', { status: 403 });
                }
                await env.FILE.put(key, request.body);
                return new Response(`Put ${key} successfully!`);

            case 'GET':
                const object = await env.FILE.get(key);

                if (object === null) {
                    return new Response('Object Not Found', { status: 404 });
                }

                const headers = new Headers();
                object.writeHttpMetadata(headers);
                headers.set('etag', object.httpEtag);

                return new Response(object.body, {
                    headers,
                });

            case 'DELETE':
                if (!hasValidHeader(request, env)) {
                    return new Response('no permission', { status: 403 });
                }
                await env.FILE.delete(key);
                return new Response('Deleted!');

            default:
                return new Response('Method Not Allowed', {
                    status: 405,
                    headers: {
                        Allow: 'PUT, GET, DELETE',
                    },
                });
        }
    }
};

/**
 * @param {Request} request
 * @param {Env} env
 * @returns {boolean}
 */
function hasValidHeader(request, env) {
    return request.headers.get('X-Custom-Auth-Key') === env.AUTH_KEY_SECRET;
};
