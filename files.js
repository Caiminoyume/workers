// 这是上传的cookie设定
const token = '';

// 这是绑定的KV空间
// env.FILE

// 使用此命令上传文件
// curl -X POST --cookie "${cookie}" -F "${path}=@${uploadfile}" https://your.workers.domain/upload
// curl -X POST --cookie "${cookie}" https://your.workers.domain/list
// curl -X POST --cookie "${cookie}" --data "${path}" https://your.workers.domain/del
// 使用此命令下载文件
// wget https://your.workers.domain/${path} 

export default {
    /**
     * @param {Request} request
     * @param {any} env
     * @param {ExecutionContext} ctx
     * @returns {Promise<Response>}
     */
    async fetch(request, env, ctx) {
        const { pathname } = new URL(request.url);
        if (request.method === 'POST') {
            const cookie = request.headers.get('Cookie');
            if (cookie === token) {
                if (pathname === '/upload') {
                    return uploadfile(await request.formData(), env);
                } else if (pathname === '/list') {
                    const value = await env.FILE.list();
                    return new Response(value.keys);
                } else if (pathname === '/del') {
                    const key = await request.text();
                    await env.FILE.delete(key);
                    return new Response(`delete ${key} success! `);
                }
                return new Response('unkown command! ');
            }
            return new Response('no permission', { status: 403 });
        }
        else if (request.method === 'GET') {
            let file = await env.FILE.get(pathname, { type: 'stream', cacheTtl: 3600 });
            if (file !== null) {
                return new Response(file);
            }
        }
        return new Response('not found', { status: 404 });
    }
};

/**
 * @param {FormData} formData
 * @param {any} env
 * @returns {Promise<Response>}
 */
async function uploadfile(formData, env) {
    let resp = [];
    for (const key of formData.keys()) {
        const file = formData.get(key);
        if (file instanceof File) {
            await env.FILE.put(key, file.stream());
            resp.push({ name: file.name, size: file.size });
        }
    }
    return new Response(JSON.stringify(resp));
}