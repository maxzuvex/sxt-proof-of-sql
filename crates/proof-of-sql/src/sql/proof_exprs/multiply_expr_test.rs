use crate::{
    base::{
        commitment::InnerProductProof,
        database::{
            owned_table_utility::*, table_utility::*, ColumnType, OwnedTableTestAccessor, TableRef,
            TableTestAccessor,
        },
        math::decimal::Precision,
    },
    proof_primitive::inner_product::curve_25519_scalar::Curve25519Scalar,
    sql::{
        proof::{exercise_verification, VerifiableQueryResult},
        proof_exprs::{multiply_expr::MultiplyExpr, test_utility::*, DynProofExpr, ProofExpr},
        proof_plans::{test_utility::*, DynProofPlan},
        AnalyzeError,
    },
};
use bumpalo::Bump;
use itertools::{multizip, MultiUnzip};
use rand::{
    distributions::{Distribution, Uniform},
    rngs::StdRng,
};
use rand_core::SeedableRng;

// select a * 2 as a, c, b * 4.5 as b, d * 3  + 4.7 as d, e from sxt.t where d * 3.9 = 8.19
#[test]
fn we_can_prove_a_typical_multiply_query() {
    let data = owned_table([
        smallint("a", [1_i16, 2, 3, 4]),
        int("b", [0_i32, 1, 2, 1]),
        varchar("e", ["ab", "t", "efg", "g"]),
        bigint("c", [0_i64, 2, 2, 0]),
        decimal75("d", 2, 1, [21_i64, 4, 21, -7]),
    ]);
    let t = TableRef::new("sxt", "t");
    let accessor =
        OwnedTableTestAccessor::<InnerProductProof>::new_from_table(t.clone(), data, 0, ());
    let ast = filter(
        vec![
            aliased_plan(multiply(column(&t, "a", &accessor), const_int(2)), "a"),
            col_expr_plan(&t, "c", &accessor),
            aliased_plan(
                multiply(column(&t, "b", &accessor), const_decimal75(2, 1, 45)),
                "b",
            ),
            aliased_plan(
                add(
                    multiply(column(&t, "d", &accessor), const_smallint(3)),
                    const_decimal75(2, 1, 47),
                ),
                "d",
            ),
            col_expr_plan(&t, "e", &accessor),
        ],
        tab(&t),
        equal(
            multiply(column(&t, "d", &accessor), const_decimal75(2, 1, 39)),
            const_decimal75(3, 2, 819),
        ),
    );
    let verifiable_res = VerifiableQueryResult::new(&ast, &accessor, &(), &[]).unwrap();
    exercise_verification(&verifiable_res, &ast, &accessor, &t);
    let res = verifiable_res
        .verify(&ast, &accessor, &(), &[])
        .unwrap()
        .table;
    let expected_res = owned_table([
        decimal75("a", 16, 0, [2_i32, 6]),
        bigint("c", [0_i64, 2]),
        decimal75("b", 13, 1, [0_i64, 90]),
        decimal75("d", 9, 1, [110_i64, 110]),
        varchar("e", ["ab", "efg"]),
    ]);
    assert_eq!(res, expected_res);
}

// select * from sxt.t where a * b * c * d * e = res
// Only the last row is a valid result
// The other two are due to the fact that scalars are elements of finite fields
// and that hence scalar multiplication inherently wraps around
#[test]
fn where_clause_can_wrap_around() {
    let data = owned_table([
        bigint(
            "a",
            [2_357_878_470_324_616_199_i64, 2_657_439_699_204_141, 884],
        ),
        bigint(
            "b",
            [31_194_601_778_911_687_i64, 1_644_425_323_726_039, 884],
        ),
        bigint("c", [500_213_946_116_239_i64, 1_570_568_673_569_987, 884]),
        bigint("d", [211_980_999_383_887_i64, 1_056_107_792_886_999, 884]),
        bigint("e", [927_908_842_441_i64, 998_426_626_609_497, 884]),
        bigint("res", [-20_i64, 50, 539_835_356_263_424]),
    ]);
    let t = TableRef::new("sxt", "t");
    let accessor =
        OwnedTableTestAccessor::<InnerProductProof>::new_from_table(t.clone(), data, 0, ());
    let ast: DynProofPlan = filter(
        cols_expr_plan(&t, &["a", "b", "c", "d", "e", "res"], &accessor),
        tab(&t),
        equal(
            multiply(
                multiply(
                    multiply(
                        multiply(column(&t, "a", &accessor), column(&t, "b", &accessor)),
                        column(&t, "c", &accessor),
                    ),
                    column(&t, "d", &accessor),
                ),
                column(&t, "e", &accessor),
            ),
            column(&t, "res", &accessor),
        ),
    );
    let verifiable_res: VerifiableQueryResult<InnerProductProof> =
        VerifiableQueryResult::new(&ast, &accessor, &(), &[]).unwrap();
    exercise_verification(&verifiable_res, &ast, &accessor, &t);
    let res = verifiable_res
        .verify(&ast, &accessor, &(), &[])
        .unwrap()
        .table;
    let expected_res = owned_table([
        bigint(
            "a",
            [2_357_878_470_324_616_199_i64, 2_657_439_699_204_141, 884],
        ),
        bigint(
            "b",
            [31_194_601_778_911_687_i64, 1_644_425_323_726_039, 884],
        ),
        bigint("c", [500_213_946_116_239_i64, 1_570_568_673_569_987, 884]),
        bigint("d", [211_980_999_383_887_i64, 1_056_107_792_886_999, 884]),
        bigint("e", [927_908_842_441_i64, 998_426_626_609_497, 884]),
        bigint("res", [-20_i64, 50, 539_835_356_263_424]),
    ]);
    assert_eq!(res, expected_res);
}

fn test_random_tables_with_given_offset(offset: usize) {
    let dist = Uniform::new(-3, 4);
    let mut rng = StdRng::from_seed([0u8; 32]);
    for _ in 0..20 {
        // Generate random table
        let n = Uniform::new(1, 21).sample(&mut rng);
        let data = owned_table([
            bigint("a", dist.sample_iter(&mut rng).take(n)),
            varchar(
                "b",
                dist.sample_iter(&mut rng).take(n).map(|v| format!("s{v}")),
            ),
            bigint("c", dist.sample_iter(&mut rng).take(n)),
            varchar(
                "d",
                dist.sample_iter(&mut rng).take(n).map(|v| format!("s{v}")),
            ),
        ]);

        // Generate random values to filter by
        let filter_val1 = format!("s{}", dist.sample(&mut rng));
        let filter_val2 = dist.sample(&mut rng);

        // Create and verify proof
        let t = TableRef::new("sxt", "t");
        let accessor = OwnedTableTestAccessor::<InnerProductProof>::new_from_table(
            t.clone(),
            data.clone(),
            offset,
            (),
        );
        let ast = filter(
            vec![
                col_expr_plan(&t, "d", &accessor),
                aliased_plan(
                    add(
                        multiply(column(&t, "a", &accessor), column(&t, "c", &accessor)),
                        const_int128(4),
                    ),
                    "f",
                ),
            ],
            tab(&t),
            and(
                equal(
                    column(&t, "b", &accessor),
                    const_scalar::<Curve25519Scalar, _>(filter_val1.as_str()),
                ),
                equal(
                    column(&t, "c", &accessor),
                    const_scalar::<Curve25519Scalar, _>(filter_val2),
                ),
            ),
        );
        let verifiable_res = VerifiableQueryResult::new(&ast, &accessor, &(), &[]).unwrap();
        exercise_verification(&verifiable_res, &ast, &accessor, &t);
        let res = verifiable_res
            .verify(&ast, &accessor, &(), &[])
            .unwrap()
            .table;

        // Calculate/compare expected result
        let (expected_f, expected_d): (Vec<_>, Vec<_>) = multizip((
            data["a"].i64_iter(),
            data["b"].string_iter(),
            data["c"].i64_iter(),
            data["d"].string_iter(),
        ))
        .filter_map(|(a, b, c, d)| {
            if b == &filter_val1 && c == &filter_val2 {
                Some((Curve25519Scalar::from(*a * *c + 4), d.clone()))
            } else {
                None
            }
        })
        .multiunzip();
        let expected_result =
            owned_table([varchar("d", expected_d), decimal75("f", 40, 0, expected_f)]);

        assert_eq!(expected_result, res);
    }
}

#[test]
fn we_can_query_random_tables_using_a_zero_offset() {
    test_random_tables_with_given_offset(0);
}

#[test]
fn we_can_query_random_tables_using_a_non_zero_offset() {
    test_random_tables_with_given_offset(23);
}

// b * (a - 1.5)
#[test]
fn we_can_compute_the_correct_output_of_a_multiply_expr_using_first_round_evaluate() {
    let alloc = Bump::new();
    let data = table([
        borrowed_smallint("a", [1_i16, 2, 3, 4], &alloc),
        borrowed_int("b", [0_i32, 1, 5, 1], &alloc),
        borrowed_varchar("d", ["ab", "t", "efg", "g"], &alloc),
        borrowed_bigint("c", [0_i64, 2, 2, 0], &alloc),
    ]);
    let t = TableRef::new("sxt", "t");
    let accessor =
        TableTestAccessor::<InnerProductProof>::new_from_table(t.clone(), data.clone(), 0, ());
    let arithmetic_expr: DynProofExpr = multiply(
        column(&t, "b", &accessor),
        subtract(
            scaling_cast(
                column(&t, "a", &accessor),
                ColumnType::Decimal75(Precision::new(6).unwrap(), 1),
            ),
            const_decimal75(2, 1, 15),
        ),
    );
    let res = arithmetic_expr
        .first_round_evaluate(&alloc, &data, &[])
        .unwrap();
    let expected_res = borrowed_decimal75("f", 18, 1, [0_i64, 5, 75, 25], &alloc).1;
    assert_eq!(res, expected_res);
}

#[test]
fn we_cannot_multiply_mismatching_types() {
    let alloc = Bump::new();
    let data = table([
        borrowed_smallint("a", [1_i16, 2, 3, 4], &alloc),
        borrowed_varchar("b", ["a", "b", "s", "z"], &alloc),
    ]);
    let t = TableRef::new("sxt", "t");
    let accessor =
        TableTestAccessor::<InnerProductProof>::new_from_table(t.clone(), data.clone(), 0, ());
    let lhs = Box::new(column(&t, "a", &accessor));
    let rhs = Box::new(column(&t, "b", &accessor));
    let multiply_err = MultiplyExpr::try_new(lhs.clone(), rhs.clone()).unwrap_err();
    assert!(matches!(
        multiply_err,
        AnalyzeError::DataTypeMismatch {
            left_type: _,
            right_type: _
        }
    ));
}
