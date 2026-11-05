/** WebAuthn no navegador: o servidor manda as opções em base64url, e a resposta do aparelho volta no mesmo formato. */

const deTexto = (texto: string) => Uint8Array.from(atob(texto.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(texto.length / 4) * 4, "=")), (c) => c.charCodeAt(0));
const paraTexto = (dado: ArrayBuffer | null) => (dado ? btoa(String.fromCharCode(...new Uint8Array(dado))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") : null);

type Opcoes = Record<string, unknown> & { challenge: string; user?: { id: string }; excludeCredentials?: { id: string }[]; allowCredentials?: { id: string }[] };

export const passkeyDisponivel = () => typeof window !== "undefined" && "PublicKeyCredential" in window && window.isSecureContext;

export async function criarPasskey(opcoes: Opcoes) {
  const publicKey = {
    ...opcoes,
    challenge: deTexto(opcoes.challenge),
    user: { ...(opcoes.user as object), id: deTexto(opcoes.user!.id) },
    excludeCredentials: (opcoes.excludeCredentials ?? []).map((c) => ({ ...c, id: deTexto(c.id) })),
  } as unknown as PublicKeyCredentialCreationOptions;
  const credencial = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential;
  const resposta = credencial.response as AuthenticatorAttestationResponse;
  return {
    id: credencial.id, rawId: paraTexto(credencial.rawId), type: credencial.type,
    response: { clientDataJSON: paraTexto(resposta.clientDataJSON), attestationObject: paraTexto(resposta.attestationObject), transports: resposta.getTransports?.() ?? [] },
  };
}

export async function usarPasskey(opcoes: Opcoes) {
  const publicKey = {
    ...opcoes,
    challenge: deTexto(opcoes.challenge),
    allowCredentials: (opcoes.allowCredentials ?? []).map((c) => ({ ...c, id: deTexto(c.id) })),
  } as unknown as PublicKeyCredentialRequestOptions;
  const credencial = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential;
  const resposta = credencial.response as AuthenticatorAssertionResponse;
  return {
    id: credencial.id, rawId: paraTexto(credencial.rawId), type: credencial.type,
    response: { clientDataJSON: paraTexto(resposta.clientDataJSON), authenticatorData: paraTexto(resposta.authenticatorData), signature: paraTexto(resposta.signature), userHandle: paraTexto(resposta.userHandle) },
  };
}
