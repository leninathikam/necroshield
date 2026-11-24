/** The production build is a static export served by the FastAPI app, so the browser talks to
 * the API on the same origin. During `next dev`, /api is proxied to the backend on port 8017. */
const isDev = process.env.NODE_ENV === "development";

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  ...(isDev
    ? { rewrites: async () => [{ source: "/api/:path*", destination: "http://127.0.0.1:8017/api/:path*" }] }
    : { output: "export", trailingSlash: true, images: { unoptimized: true } }),
};

export default nextConfig;
