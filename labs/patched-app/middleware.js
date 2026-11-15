import { NextResponse } from 'next/server'

// Protect /dashboard: the authorization check lives ONLY in middleware.
// This mirrors the common (and, with CVE-2025-29927, dangerous) pattern of
// treating Next.js middleware as a hard security boundary.
export function middleware(request) {
  const authed = request.cookies.get('session')?.value === 'valid-user'
  if (!authed) {
    const url = request.nextUrl.clone()
    url.pathname = '/login'
    return NextResponse.redirect(url)
  }
  return NextResponse.next()
}

export const config = {
  matcher: ['/dashboard/:path*'],
}
