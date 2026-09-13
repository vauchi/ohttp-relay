// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for bounded request body reading.
//!
//! `read_bounded_body` is the relay's guard against unbounded request bodies.
//! It has two rejection paths — a fast reject on an oversized
//! `Content-Length`, and the limit enforced while reading — and the router
//! maps both to 413. These exercise the two paths and their boundary
//! directly, which the router tests cannot distinguish.

use axum::body::Body;
use axum::extract::Request;
use axum::http::header;
use vauchi_ohttp_relay::request::{BodyLimitError, read_bounded_body};

const LIMIT: usize = 64;

fn request_with_body(bytes: Vec<u8>) -> Request {
    Request::builder()
        .method("POST")
        .uri("/")
        .body(Body::from(bytes))
        .expect("valid test request")
}

/// A body whose declared `Content-Length` disagrees with what is sent; only
/// the header is used by the fast-reject path.
fn request_declaring(content_length: &str, bytes: Vec<u8>) -> Request {
    Request::builder()
        .method("POST")
        .uri("/")
        .header(header::CONTENT_LENGTH, content_length)
        .body(Body::from(bytes))
        .expect("valid test request")
}

// @internal
#[tokio::test]
async fn a_body_under_the_limit_is_returned_intact() {
    let payload = vec![7u8; LIMIT - 1];

    let body = read_bounded_body(request_with_body(payload.clone()), LIMIT)
        .await
        .expect("body under the limit should be accepted");

    assert_eq!(body.as_ref(), payload.as_slice());
}

// @internal
#[tokio::test]
async fn a_body_at_exactly_the_limit_is_accepted() {
    let payload = vec![7u8; LIMIT];

    let body = read_bounded_body(request_with_body(payload.clone()), LIMIT)
        .await
        .expect("body at the limit should be accepted");

    assert_eq!(body.len(), LIMIT);
}

// @internal
#[tokio::test]
async fn a_body_one_byte_over_the_limit_is_rejected() {
    let result = read_bounded_body(request_with_body(vec![7u8; LIMIT + 1]), LIMIT).await;

    match result {
        Err(BodyLimitError::BodyReadFailed { .. }) => {}
        other => panic!("expected BodyReadFailed, got {other:?}"),
    }
}

// @internal
#[tokio::test]
async fn an_empty_body_is_accepted() {
    let body = read_bounded_body(request_with_body(Vec::new()), LIMIT)
        .await
        .expect("an empty body should be accepted");

    assert!(body.is_empty());
}

// @internal
#[tokio::test]
async fn a_zero_limit_accepts_only_an_empty_body() {
    let empty = read_bounded_body(request_with_body(Vec::new()), 0)
        .await
        .expect("an empty body should satisfy a zero limit");
    assert!(empty.is_empty());

    let result = read_bounded_body(request_with_body(vec![7u8]), 0).await;
    assert!(result.is_err(), "a zero limit must reject any content");
}

// @internal
#[tokio::test]
async fn an_oversized_content_length_is_rejected_before_reading() {
    // The declared length is what triggers the reject; the body here is well
    // under the limit, so only the header can explain the rejection.
    let result = read_bounded_body(request_declaring("1000", vec![7u8; 8]), LIMIT).await;

    match result {
        Err(BodyLimitError::ContentLengthExceeded { content_length }) => {
            assert_eq!(content_length, 1000);
        }
        other => panic!("expected ContentLengthExceeded, got {other:?}"),
    }
}

// @internal
#[tokio::test]
async fn a_content_length_at_exactly_the_limit_is_not_fast_rejected() {
    let payload = vec![7u8; LIMIT];

    let body = read_bounded_body(request_declaring(&LIMIT.to_string(), payload), LIMIT)
        .await
        .expect("Content-Length at the limit should not be rejected");

    assert_eq!(body.len(), LIMIT);
}

// @internal
#[tokio::test]
async fn a_content_length_one_over_the_limit_is_fast_rejected() {
    let over = LIMIT + 1;

    let result =
        read_bounded_body(request_declaring(&over.to_string(), vec![7u8; over]), LIMIT).await;

    match result {
        Err(BodyLimitError::ContentLengthExceeded { content_length }) => {
            assert_eq!(content_length, over);
        }
        other => panic!("expected ContentLengthExceeded, got {other:?}"),
    }
}

/// An unparsable `Content-Length` must not be treated as "small enough" and
/// must not bypass the read limit either — the body itself is still bounded.
// @internal
#[tokio::test]
async fn an_unparsable_content_length_falls_through_to_the_read_limit() {
    for declared in ["not-a-number", "-1", "1e9", "", "18446744073709551616"] {
        let result =
            read_bounded_body(request_declaring(declared, vec![7u8; LIMIT + 1]), LIMIT).await;

        match result {
            Err(BodyLimitError::BodyReadFailed { .. }) => {}
            other => panic!("declared {declared:?}: expected BodyReadFailed, got {other:?}"),
        }
    }
}

// @internal
#[tokio::test]
async fn an_understated_content_length_does_not_let_an_oversized_body_through() {
    // A client that lies low about its size still has to get past the read
    // limit, which is enforced on the bytes actually delivered.
    let result = read_bounded_body(request_declaring("1", vec![7u8; LIMIT + 1]), LIMIT).await;

    assert!(
        result.is_err(),
        "an understated Content-Length must not bypass the read limit"
    );
}

// @internal
#[tokio::test]
async fn the_two_rejection_paths_report_distinct_kinds() {
    let fast = read_bounded_body(request_declaring("1000", vec![7u8; 8]), LIMIT)
        .await
        .expect_err("oversized Content-Length should be rejected");
    let streamed = read_bounded_body(request_with_body(vec![7u8; LIMIT + 1]), LIMIT)
        .await
        .expect_err("oversized body should be rejected");

    assert_eq!(fast.kind(), "content_length");
    assert_eq!(streamed.kind(), "body_read");
    assert_ne!(fast.kind(), streamed.kind());
}
