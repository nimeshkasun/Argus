import { describe, expect, it } from 'vitest';
import { htmlToText, parseFeed } from '../../src/intel/feed-parser';
import { isValidRange } from '../../src/scanning/versions';

describe('news feed parsing', () => {
  it('reads Atom entries with typed titles, alternate links and HTML content', () => {
    const atom = `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>X</title>
      <entry><id>urn:1</id><title type="html">Fix for &lt;b&gt;tar&lt;/b&gt;</title>
        <link rel="self" href="https://x/self"/><link rel="alternate" href="https://x/post"/>
        <published>2026-10-01T00:00:00Z</published><content type="html">&lt;p&gt;tar &amp;lt; 6.2.1 is affected&lt;/p&gt;</content></entry>
      <entry><id>urn:2</id><title>Javascript link</title><link href="javascript:alert(1)"/><summary>s</summary></entry>
    </feed>`;
    const [a, b] = parseFeed(atom);
    expect(a).toMatchObject({ title: 'Fix for tar', link: 'https://x/post', summary: 'tar < 6.2.1 is affected' });
    expect(a.publishedAt?.toISOString()).toBe('2026-10-01T00:00:00.000Z');
    expect(a.guid).toMatch(/^[0-9a-f]{64}$/);
    expect(b.link).toBeNull();
  });

  it('reads RSS 1.0 (RDF) and rejects documents that are not feeds', () => {
    const rdf = `<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">
      <item><title>One</title><link>https://x/1</link><dc:date>2026-10-02T00:00:00Z</dc:date><description>d</description></item></rdf:RDF>`;
    expect(parseFeed(rdf)).toEqual([expect.objectContaining({ title: 'One', link: 'https://x/1', summary: 'd' })]);
    expect(() => parseFeed('<html><body>not a feed</body></html>')).toThrow(/Not an RSS or Atom feed/);
  });

  it('ignores DOCTYPE entity declarations (no entity expansion from untrusted feeds)', () => {
    const lol = `<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY a "AAAAAAAAAA"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>
      <rss version="2.0"><channel><item><title>T &amp; &a; &c;</title><description>x</description></item></channel></rss>`;
    const [e] = parseFeed(lol);
    expect(e.title).not.toContain('AAAA');
    expect(e.title.length).toBeLessThan(20);
  });

  it('turns HTML into plain text and validates advisory ranges', () => {
    expect(htmlToText('<style>p{}</style><p>a&nbsp;&amp;&#33;</p><ul><li>x</li><li>y</li></ul>')).toBe('a &!\nx\ny');
    expect(isValidRange('npm', '<4.17.21')).toBe(true);
    expect(isValidRange('npm', '>=2.0.0 <2.3.1 || >=3.0.0 <3.0.2')).toBe(true);
    expect(isValidRange('npm', 'not a range')).toBe(false);
  });
});
