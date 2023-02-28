import { getInput, setFailed, setOutput, setSecret } from '@actions/core';
import { createSign } from 'crypto';
import { ClientRequest } from 'http';
import { request, RequestOptions } from 'https';
import { format } from 'util';

type JWTHeader = {
  alg: 'RS256';
  typ: 'JWT';
};

type JWTPayload = {
  iat: number;
  exp: number;
  iss: string;
};

function base64(obj: JWTHeader | JWTPayload, enc: BufferEncoding): string {
  const json: string = JSON.stringify(obj);
  return urlBase64(Buffer.from(json, enc).toString('base64'));
}

function urlBase64(input: string): string {
  return input.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function getJWT(appID: string, privateKey: string): string {
  const header: JWTHeader = {
    alg: 'RS256',
    typ: 'JWT',
  };
  const timestamp: number = Math.floor(Date.now() / 1000);
  const payload: JWTPayload = {
    iat: timestamp - 60,
    exp: timestamp + 600,
    iss: appID,
  };
  const content: string = format(
    '%s.%s',
    base64(header, 'binary'),
    base64(payload, 'utf-8'),
  );
  const signature = createSign('RSA-SHA256')
    .update(content)
    .sign(privateKey, 'base64');
  return format('%s.%s', content, urlBase64(signature));
}

type Installations = {
  id: number;
  account: {
    login: string;
    id: number;
  };
}[];

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace NodeJS {
    interface ProcessEnv {
      GITHUB_REPOSITORY_OWNER_ID: string;
      GITHUB_OUTPUT: string;
    }
  }
}

async function requestApi<Type>(opts: RequestOptions): Promise<Type> {
  return new Promise<Type>((resolve, reject) => {
    let responseBody = '';
    const req: ClientRequest = request(opts, (response) => {
      response.setEncoding('utf-8');
      response.on('data', (chunk) => {
        responseBody += chunk;
      });
      response.on('end', () => {
        resolve(JSON.parse(responseBody));
      });
      response.on('error', (err) => {
        reject(err);
      });
    });
    req.on('error', (err) => {
      reject(err);
    });
    req.on('timeout', () => {
      req.destroy();
    });
    req.end();
  });
}

async function getInstallation(
  jwt: string,
  repoOwnerID: number,
): Promise<number> {
  const reqOptions: RequestOptions = {
    method: 'GET',
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: format('Bearer %s', jwt),
    },
    host: 'api.github.com',
    path: '/app/installations',
  };
  const execRequest = await requestApi<Installations>(reqOptions);
  const obj = execRequest.find(
    (installation) => installation.account.id === repoOwnerID,
  );
  if (obj === undefined) throw new Error('no installation found');
  return obj.id;
}

type InstallationAccessToken = {
  token: string;
};

async function getToken(jwt: string, installation: number): Promise<string> {
  const reqOptions: RequestOptions = {
    method: 'POST',
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: format('Bearer %s', jwt),
    },
    host: 'api.github.com',
    path: format('/app/installations/%s/access_tokens', installation),
  };
  const execRequest = await requestApi<InstallationAccessToken>(reqOptions);
  return execRequest.token;
}

async function main(): Promise<void> {
  try {
    const appID: string = getInput('app_id', { required: true });
    const appKey: string = getInput('app_key_pem', { required: true });
    setSecret(appKey);
    const jwt: string = getJWT(appID, appKey);
    const repoOwnerID: number = parseInt(
      process.env.GITHUB_REPOSITORY_OWNER_ID,
    );
    const installation: number = await getInstallation(jwt, repoOwnerID);
    const token: string = await getToken(jwt, installation);
    setSecret(token);
    setOutput('token', token);
  } catch (e) {
    if (e instanceof Error) setFailed(e.message);
  }
}

main();
