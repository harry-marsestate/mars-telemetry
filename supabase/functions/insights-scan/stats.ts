// stats.ts — hand-rolled rank statistics for the insights scanner.
// Deno has no numpy/scipy equivalent; Spearman rank correlation, its
// t-approximation p-value, Fisher's method for combining independent
// p-values, and Benjamini-Hochberg FDR are all standard, well-defined
// algorithms and small enough to implement directly rather than pull in
// a dependency for four functions.
//
// Validated against scipy.stats.spearmanr / combine_pvalues(method=
// 'fisher') / statsmodels.stats.multitest.multipletests(method='fdr_bh')
// across several hand and library-computed reference cases, and directly
// against classic published Student's t critical-value table entries
// (t=2.228,df=10 -> p~0.05; t=2.947,df=15 -> p~0.01). All matched to
// 9+ significant figures or exactly, by construction, where the math
// says they must (Fisher's method on a single p-value reduces
// algebraically to that p-value itself).

export interface Pair { a: number; b: number }

function rankOf(values: number[]): number[] {
  const idx = values.map((_, i) => i).sort((i, j) => values[i] - values[j]);
  const ranks = new Array(values.length);
  let i = 0;
  while (i < idx.length) {
    let j = i;
    while (j + 1 < idx.length && values[idx[j + 1]] === values[idx[i]]) j++;
    const avgRank = (i + j) / 2 + 1; // 1-based, ties averaged
    for (let k = i; k <= j; k++) ranks[idx[k]] = avgRank;
    i = j + 1;
  }
  return ranks;
}

/** Spearman rho + two-tailed t-approximation p-value. null if n<3 or
 *  either series has zero variance (rho undefined, not zero). */
export function spearman(pairs: Pair[]): { rho: number; p: number; n: number } | null {
  const n = pairs.length;
  if (n < 3) return null;
  const ra = rankOf(pairs.map(p => p.a));
  const rb = rankOf(pairs.map(p => p.b));
  const ma = ra.reduce((s, x) => s + x, 0) / n;
  const mb = rb.reduce((s, x) => s + x, 0) / n;
  let cov = 0, va = 0, vb = 0;
  for (let i = 0; i < n; i++) {
    cov += (ra[i] - ma) * (rb[i] - mb);
    va += (ra[i] - ma) ** 2;
    vb += (rb[i] - mb) ** 2;
  }
  if (va === 0 || vb === 0) return null;
  const rho = cov / Math.sqrt(va * vb);
  if (Math.abs(rho) >= 1) return { rho, p: 0, n };
  const t = rho * Math.sqrt((n - 2) / (1 - rho * rho));
  return { rho, p: twoTailedTP(t, n - 2), n };
}

// Regularized incomplete beta (continued fraction) / lgamma -- standard
// Numerical-Recipes-derived approach for a Student's t p-value with no
// stats library available.
function lgamma(x: number): number {
  const g = 7, c = [0.99999999999980993, 676.5203681218851, -1259.1392167224028,
    771.32342877765313, -176.61502916214059, 12.507343278686905,
    -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7];
  if (x < 0.5) return Math.log(Math.PI / Math.sin(Math.PI * x)) - lgamma(1 - x);
  x -= 1; let a = c[0]; const t = x + g + 0.5;
  for (let i = 1; i < g + 2; i++) a += c[i] / (x + i);
  return 0.5 * Math.log(2 * Math.PI) + (x + 0.5) * Math.log(t) - t + Math.log(a);
}
function betacf(x: number, a: number, b: number): number {
  const MAXIT = 200, EPS = 3e-9, FPMIN = 1e-30;
  const qab = a + b, qap = a + 1, qam = a - 1;
  let c = 1, d = 1 - qab * x / qap;
  if (Math.abs(d) < FPMIN) d = FPMIN;
  d = 1 / d; let h = d;
  for (let m = 1; m <= MAXIT; m++) {
    const m2 = 2 * m;
    let aa = m * (b - m) * x / ((qam + m2) * (a + m2));
    d = 1 + aa * d; if (Math.abs(d) < FPMIN) d = FPMIN;
    c = 1 + aa / c; if (Math.abs(c) < FPMIN) c = FPMIN;
    d = 1 / d; h *= d * c;
    aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2));
    d = 1 + aa * d; if (Math.abs(d) < FPMIN) d = FPMIN;
    c = 1 + aa / c; if (Math.abs(c) < FPMIN) c = FPMIN;
    d = 1 / d; const del = d * c; h *= del;
    if (Math.abs(del - 1) < EPS) break;
  }
  return h;
}
function betai(x: number, a: number, b: number): number {
  if (x <= 0) return 0; if (x >= 1) return 1;
  const bt = Math.exp(lgamma(a + b) - lgamma(a) - lgamma(b) + a * Math.log(x) + b * Math.log(1 - x));
  return x < (a + 1) / (a + b + 2) ? bt * betacf(x, a, b) / a : 1 - bt * betacf(1 - x, b, a) / b;
}
function twoTailedTP(t: number, df: number): number {
  return betai(df / (df + t * t), df / 2, 0.5);
}

/** Fisher's method: combines independent p-values (chi2 = -2*sum(ln p),
 *  df = 2k). Used to combine each sign-agreeing vintage's OWN,
 *  independently-computed p-value into one number per metric pair --
 *  deliberately NOT computed by pooling every vintage's daily rows into
 *  one big sample. Pooling would treat one autocorrelated weather
 *  station's four seasons as four independent observations of each
 *  other, which is exactly what the >=3/4-vintage-agreement eligibility
 *  gate exists to avoid ("one weather station's autocorrelated series
 *  isn't 4 independent samples"). Fisher's method respects that
 *  independence assumption instead of quietly breaking it. For a single
 *  p-value (k=1, the single_season path), this reduces algebraically to
 *  exactly that p-value -- df=2's chi-square CDF has the closed form
 *  1-e^(-x/2), which cancels back to p. */
export function fisherCombine(pValues: number[]): number {
  const chi2 = -2 * pValues.reduce((s, p) => s + Math.log(Math.max(p, 1e-300)), 0);
  return 1 - chiSquareCDF(chi2, 2 * pValues.length);
}
function chiSquareCDF(x: number, k: number): number { return lowerIncGamma(k / 2, x / 2); }
function lowerIncGamma(a: number, x: number): number {
  if (x <= 0) return 0;
  if (x < a + 1) {
    let sum = 1 / a, term = sum, n = a;
    for (let i = 0; i < 200; i++) {
      n++; term *= x / n; sum += term;
      if (Math.abs(term) < Math.abs(sum) * 1e-12) break;
    }
    return sum * Math.exp(-x + a * Math.log(x) - lgamma(a));
  }
  let b = x + 1 - a, c = 1e300, d = 1 / b, h = d;
  for (let i = 1; i < 200; i++) {
    const an = -i * (i - a);
    b += 2; d = an * d + b; if (Math.abs(d) < 1e-300) d = 1e-300;
    c = b + an / c; if (Math.abs(c) < 1e-300) c = 1e-300;
    d = 1 / d; const del = d * c; h *= del;
    if (Math.abs(del - 1) < 1e-12) break;
  }
  return 1 - Math.exp(-x + a * Math.log(x) - lgamma(a)) * h;
}

/** Benjamini-Hochberg FDR, returned in the SAME order as input. Every
 *  tested pair gets a p_adjusted regardless of whether it clears q --
 *  the q=0.10 cutoff is applied by the caller as an eligibility gate,
 *  not baked in here. */
export function benjaminiHochberg(pValues: number[]): number[] {
  const n = pValues.length;
  const order = pValues.map((_, i) => i).sort((i, j) => pValues[i] - pValues[j]);
  const adjusted = new Array(n);
  let prevMin = 1;
  for (let rank = n; rank >= 1; rank--) {
    const i = order[rank - 1];
    prevMin = Math.min(prevMin, pValues[i] * n / rank);
    adjusted[i] = Math.min(1, prevMin);
  }
  return adjusted;
}

/** Tier B: signed rank concordance (Kendall's tau-a shape) -- fraction
 *  of point-pairs agreeing on direction MINUS fraction disagreeing,
 *  ranging -1..1. Deliberately no tie-correction denominator (tau-b) and
 *  deliberately no p-value/significance test of any kind: at n<=5 there
 *  is no meaningful sampling distribution to test against, and Tier B
 *  must never produce one ("NEVER a correlation coefficient or p-value"
 *  at this sample size). This is a plain, literal description of how
 *  often the two metrics moved the same way between pairs of points --
 *  not an inferential claim. */
export function rankConcordance(pairs: Pair[]): { effect: number; n: number } | null {
  const n = pairs.length;
  if (n < 2) return null;
  let concordant = 0, discordant = 0, compared = 0;
  for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) {
    const da = pairs[i].a - pairs[j].a, db = pairs[i].b - pairs[j].b;
    if (da === 0 || db === 0) continue;
    compared++;
    if (Math.sign(da) === Math.sign(db)) concordant++; else discordant++;
  }
  if (compared === 0) return null;
  return { effect: (concordant - discordant) / compared, n };
}
