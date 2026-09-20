// PostgREST casts NUMERIC to text before JSON encoding: no binary floating
// point conversion and no loss of sub-cent invoice amounts. Arithmetic here
// uses a common decimal scale and integer sums; only display values round.
type Category = { labor_hours: string; labor_cost: string; expense_cost: string };

function parts(value: string): [bigint, number] {
  if (!/^-?\d+(\.\d+)?$/.test(value)) throw new Error("Invalid labour decimal");
  const [whole, fraction = ""] = value.split(".");
  return [BigInt(whole + fraction), fraction.length];
}

function decimal(value: bigint, scale: number): string {
  const sign = value < 0n ? "-" : "";
  const digits = (value < 0n ? -value : value).toString().padStart(scale + 1, "0");
  return sign + (scale ? `${digits.slice(0, -scale)}.${digits.slice(-scale)}` : digits);
}

// Half away from zero, including credits. The denominator is positive.
function roundedRatio(numerator: bigint, denominator: bigint): string {
  const negative = numerator < 0n;
  const cents = (negative ? -numerator : numerator) * 100n;
  const rounded = (cents * 2n + denominator) / (denominator * 2n);
  return decimal(negative ? -rounded : rounded, 2);
}

export function labourResult(categories: Category[], scope: Record<string, unknown>): string {
  const fields = ["labor_hours", "labor_cost", "expense_cost"] as const;
  const values = categories.flatMap(row => fields.map(field => parts(row[field])));
  const scale = Math.max(0, ...values.map(([, s]) => s));
  const unit = 10n ** BigInt(scale);
  const sums = fields.map((_, i) => values.reduce((sum, [v, s], index) =>
    index % fields.length === i ? sum + v * 10n ** BigInt(scale - s) : sum, 0n));
  const [hours, labor, expense] = sums;
  const combined = labor + expense;
  const rate = hours === 0n ? null : roundedRatio(hours < 0n ? -labor : labor, hours < 0n ? -hours : hours);
  return JSON.stringify({
    scope,
    record_status: categories.length ? "records_present" : "no_records",
    totals: {
      labor_hours: decimal(hours, scale),
      labor_cost: decimal(labor, scale),
      expense_cost: decimal(expense, scale),
      total_cost: decimal(combined, scale),
      cost_per_hour: rate,
      cost_per_hour_note: "Labour cost / labour hours, rounded to two decimals; null when hours are zero. Expenses excluded.",
      display: {
        labor_hours: roundedRatio(hours, unit),
        labor_cost: roundedRatio(labor, unit),
        expense_cost: roundedRatio(expense, unit),
        total_cost: roundedRatio(combined, unit),
        cost_per_hour: rate,
      },
    },
    categories,
  });
}
