import assert from 'node:assert/strict';

// p: sorted task ids (native order), rootOf: Map childId -> rootId (only descendants), target: logical visible count
export function effectiveLimit(p, rootOf, target) {
  const idx = new Map(p.map((id, i) => [id, i]));
  let L = Math.min(target, p.length);
  for (;;) {
    let shown = 0;
    for (let i = 0; i < L; i++) {
      const r = rootOf.get(p[i]);
      const suppressed = r !== undefined && idx.has(r) && idx.get(r) < L;
      if (!suppressed) shown++;
    }
    if (shown >= Math.min(target, p.length) || L >= p.length) {
      // remaining all suppressed? reveal to end to avoid an empty "show more"
      let restVisible = 0;
      for (let i = L; i < p.length; i++) {
        const r = rootOf.get(p[i]);
        if (!(r !== undefined && idx.has(r))) restVisible++;
      }
      return restVisible === 0 ? p.length : L;
    }
    L++;
  }
}

const cases = [
  [
    'children before parent (active children newer)',
    ['c1', 'c2', 'a', 'b', 'P', 'd', 'e', 'f'],
    [['c1', 'P'], ['c2', 'P']],
    5,
    { L: 7, visible: 'a,b,P,d,e', showMore: true },
  ],
  [
    'children beyond 5',
    ['P', 'a', 'b', 'c', 'd', 'c1', 'e', 'c2'],
    [['c1', 'P'], ['c2', 'P']],
    5,
    { L: 5, visible: 'P,a,b,c,d', showMore: true },
  ],
  [
    'no tree',
    ['a', 'b', 'c', 'd', 'e', 'f'],
    [],
    5,
    { L: 5, visible: 'a,b,c,d,e', showMore: true },
  ],
  [
    'only children left',
    ['P', 'a', 'b', 'c', 'd', 'c1', 'c2'],
    [['c1', 'P'], ['c2', 'P']],
    5,
    { L: 7, visible: 'P,a,b,c,d', showMore: false },
  ],
  [
    'parent not in list (other project)',
    ['c1', 'a', 'b', 'c', 'd', 'e'],
    [['c1', 'X']],
    5,
    { L: 5, visible: 'c1,a,b,c,d', showMore: true },
  ],
  [
    'timeline step 20 with suppressed children',
    [
      'c1', 'c2', 'P', 't01', 't02', 't03', 't04', 't05', 't06', 't07',
      't08', 't09', 't10', 't11', 't12', 't13', 't14', 't15', 't16', 't17',
      't18', 't19',
    ],
    [['c1', 'P'], ['c2', 'P']],
    20,
    {
      L: 22,
      visible: 'P,t01,t02,t03,t04,t05,t06,t07,t08,t09,t10,t11,t12,t13,t14,t15,t16,t17,t18,t19',
      showMore: false,
    },
  ],
  [
    'archived middle node leaves grandchild top-level',
    ['P', 'gc1', 'a', 'b', 'c', 'd'],
    [],
    5,
    { L: 5, visible: 'P,gc1,a,b,c', showMore: true },
  ],
];

for (const [name, p, pairs, t, expected] of cases) {
  const rootOf = new Map(pairs);
  const L = effectiveLimit(p, rootOf, t);
  const idx = new Map(p.map((id, i) => [id, i]));
  const visible = p
    .slice(0, L)
    .filter(id => {
      const r = rootOf.get(id);
      return !(r !== undefined && idx.has(r) && idx.get(r) < L);
    });
  const showMore = p.length > L;
  console.log(
    name.padEnd(48),
    'L=',
    L,
    'visibleTopLevel=',
    visible.join(','),
    'showMore=',
    showMore
  );
  assert.equal(L, expected.L, `${name}: expected L=${expected.L}, got ${L}`);
  assert.equal(visible.join(','), expected.visible, `${name}: visible mismatch`);
  assert.equal(showMore, expected.showMore, `${name}: showMore mismatch`);
}
