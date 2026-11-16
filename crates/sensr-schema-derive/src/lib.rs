//! `#[derive(SensrModel)]` and `#[derive(SensrOptions)]`.
//!
//! The model derive turns `#[sensr(...)]` attributes into model metadata,
//! defaults, validation with dotted paths (presence, ranges, nested models,
//! the cross-field constraints and collection-wide uniqueness) and raw-text
//! validation with the model's messages. OPNsense's `lint-model` rules
//! (`Mk/lint.mk`) become compile errors here, so a model that would fail
//! upstream's lint does not build (T-0348..T-0363).
//!
//! Struct attributes: `description = "..."` (required, one line),
//! `version = "x.y.z"`.
//!
//! Field attributes: `required`, `default = "text"`, `message = "..."`,
//! `range(min = N, max = N)`, `nested`, `multiple`, `blank_desc = "..."`,
//! `separator = "..."`, `as_list`, and constraints `unique`,
//! `unique(with(a, b), message = "...", case_insensitive)`,
//! `all_or_none(with(..), message = "...")`,
//! `single_select(with(..), message = "...")`, `set(with(..), message = "...")`,
//! `depend(with(..), message = "...")`,
//! `set_if(field = x, check = "...", message = "...")`,
//! `compared(field = x, op = "lt", message = "...")`.

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::meta::ParseNestedMeta;
use syn::{
    Data, DeriveInput, Error, Fields, Ident, LitBool, LitInt, LitStr, Result, Type,
    parse_macro_input,
};

/// See the crate documentation.
#[proc_macro_derive(SensrModel, attributes(sensr))]
pub fn derive_model(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    model(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// Option metadata for an enum: `options()` lists `(key, label)` pairs from
/// `#[sensr(label = "...")]` on each variant; keys are the serde names.
#[proc_macro_derive(SensrOptions, attributes(sensr))]
pub fn derive_options(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    options(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

fn lint(span: Span, rule: u8, text: &str) -> Error {
    Error::new(span, format!("lint-model rule {rule}: {text}"))
}

/// `with(a, b)` inside a constraint.
fn parse_with(meta: &ParseNestedMeta<'_>) -> Result<Vec<Ident>> {
    let mut out = Vec::new();
    meta.parse_nested_meta(|m| {
        out.push(
            m.path
                .get_ident()
                .cloned()
                .ok_or_else(|| m.error("expected a field name"))?,
        );
        Ok(())
    })?;
    Ok(out)
}

/// Accepts `name` or `name = true`; `name = false` restates the default,
/// which lint rule `rule` forbids.
fn reject_false(meta: &ParseNestedMeta<'_>, rule: u8, text: &str) -> Result<()> {
    if let Some(b) = parse_flag(meta)?
        && !b.value
    {
        return Err(lint(b.span(), rule, text));
    }
    Ok(())
}

fn parse_flag(meta: &ParseNestedMeta<'_>) -> Result<Option<LitBool>> {
    if meta.input.peek(syn::Token![=]) {
        Ok(Some(meta.value()?.parse()?))
    } else {
        Ok(None)
    }
}

fn check_message(m: &LitStr) -> Result<()> {
    let v = m.value();
    if !v.ends_with('.') {
        return Err(lint(
            m.span(),
            14,
            "a validation message must end with a period",
        ));
    }
    if !v.starts_with(|c: char| c.is_uppercase()) {
        return Err(lint(
            m.span(),
            15,
            "a validation message must start with an upper-case letter",
        ));
    }
    Ok(())
}

#[derive(Default)]
struct Constraint {
    kind: String,
    with: Vec<Ident>,
    field: Option<Ident>,
    check: Option<LitStr>,
    op: Option<LitStr>,
    message: Option<LitStr>,
    case_insensitive: bool,
}

#[derive(Default)]
struct FieldAttrs {
    required: bool,
    default: Option<LitStr>,
    message: Option<LitStr>,
    range: Option<(LitInt, LitInt)>,
    nested: bool,
    multiple: bool,
    blank_desc: Option<LitStr>,
    constraints: Vec<Constraint>,
}

fn parse_constraint(kind: &str, meta: &ParseNestedMeta<'_>) -> Result<Constraint> {
    let mut c = Constraint {
        kind: kind.to_owned(),
        ..Constraint::default()
    };
    if !meta.input.peek(syn::token::Paren) {
        if kind == "unique" {
            return Ok(c);
        }
        return Err(meta.error(format!("{kind}(...) needs arguments")));
    }
    meta.parse_nested_meta(|m| {
        if m.path.is_ident("with") {
            c.with = parse_with(&m)?;
        } else if m.path.is_ident("message") {
            let lit: LitStr = m.value()?.parse()?;
            check_message(&lit)?;
            c.message = Some(lit);
        } else if m.path.is_ident("field") {
            c.field = Some(m.value()?.parse()?);
        } else if m.path.is_ident("check") {
            c.check = Some(m.value()?.parse()?);
        } else if m.path.is_ident("op") {
            let op: LitStr = m.value()?.parse()?;
            if !["gt", "gte", "lt", "lte", "eq", "neq"].contains(&op.value().as_str()) {
                return Err(Error::new(
                    op.span(),
                    "op must be one of gt, gte, lt, lte, eq, neq",
                ));
            }
            c.op = Some(op);
        } else if m.path.is_ident("case_insensitive") {
            c.case_insensitive = true;
        } else {
            return Err(m.error("unknown constraint argument"));
        }
        Ok(())
    })?;
    match kind {
        "set_if" if c.field.is_none() || c.check.is_none() => {
            Err(meta.error("set_if needs field = .. and check = \"..\""))
        }
        "compared" if c.field.is_none() || c.op.is_none() => {
            Err(meta.error("compared needs field = .. and op = \"..\""))
        }
        "all_or_none" | "single_select" | "set" | "depend" if c.with.is_empty() => {
            Err(meta.error(format!("{kind} needs with(...)")))
        }
        _ => Ok(c),
    }
}

fn field_attrs(field: &syn::Field) -> Result<FieldAttrs> {
    let mut a = FieldAttrs::default();
    let mut required_span = None;
    let mut multiple_span = None;
    for attr in field.attrs.iter().filter(|a| a.path().is_ident("sensr")) {
        attr.parse_nested_meta(|meta| {
            let span = meta
                .path
                .get_ident()
                .map_or_else(Span::call_site, Ident::span);
            let p = |n: &str| meta.path.is_ident(n);
            if p("required") {
                reject_false(&meta, 8, "required = false is the default; leave it out")?;
                a.required = true;
                required_span = Some(span);
            } else if p("multiple") {
                reject_false(&meta, 7, "multiple = false is the default; leave it out")?;
                a.multiple = true;
                multiple_span = Some(span);
            } else if p("as_list") {
                reject_false(&meta, 13, "as_list = false is the default; leave it out")?;
            } else if p("separator") {
                let s: LitStr = meta.value()?.parse()?;
                if s.value() == "," {
                    return Err(lint(
                        s.span(),
                        12,
                        "separator = \",\" is the default; leave it out",
                    ));
                }
            } else if p("default") {
                let s: LitStr = meta.value()?.parse()?;
                if s.value().is_empty() {
                    return Err(lint(
                        s.span(),
                        3,
                        "an empty default is not a default; leave it out",
                    ));
                }
                a.default = Some(s);
            } else if p("blank_desc") {
                let s: LitStr = meta.value()?.parse()?;
                if s.value() == "None" {
                    return Err(lint(
                        s.span(),
                        4,
                        "blank_desc = \"None\" is the default; leave it out",
                    ));
                }
                a.blank_desc = Some(s);
            } else if p("message") {
                let s: LitStr = meta.value()?.parse()?;
                check_message(&s)?;
                a.message = Some(s);
            } else if p("range") {
                let (mut min, mut max) = (None, None);
                meta.parse_nested_meta(|m| {
                    if m.path.is_ident("min") {
                        min = Some(m.value()?.parse::<LitInt>()?);
                    } else if m.path.is_ident("max") {
                        max = Some(m.value()?.parse::<LitInt>()?);
                    } else {
                        return Err(m.error("range takes min and max"));
                    }
                    Ok(())
                })?;
                let min = min.unwrap_or_else(|| LitInt::new("-9223372036854775808", span));
                let max = max.unwrap_or_else(|| LitInt::new("9223372036854775807", span));
                a.range = Some((min, max));
            } else if p("nested") {
                a.nested = true;
            } else if let Some(kind) = [
                "unique",
                "all_or_none",
                "single_select",
                "set",
                "depend",
                "set_if",
                "compared",
            ]
            .into_iter()
            .find(|k| meta.path.is_ident(k))
            {
                a.constraints.push(parse_constraint(kind, &meta)?);
            } else {
                return Err(meta.error("unknown sensr attribute"));
            }
            Ok(())
        })?;
    }
    if let Some(d) = &a.default
        && !a.required
    {
        return Err(lint(
            d.span(),
            2,
            "a default on a field that is not required is spurious; mark it required or drop the default",
        ));
    }
    if let Some(b) = &a.blank_desc {
        if required_span.is_some() {
            return Err(lint(
                b.span(),
                5,
                "blank_desc does not apply to a required field",
            ));
        }
        if multiple_span.is_some() {
            return Err(lint(
                b.span(),
                6,
                "blank_desc does not apply to a multiple field",
            ));
        }
    }
    Ok(a)
}

/// The field's name in JSON: `#[serde(rename = "...")]` or the identifier.
fn json_name(field: &syn::Field) -> Result<String> {
    let mut name = field
        .ident
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default();
    for attr in field.attrs.iter().filter(|a| a.path().is_ident("serde")) {
        // Ignore serde arguments we do not care about.
        let _ = attr.parse_nested_meta(|m| {
            if m.path.is_ident("rename") {
                let s: LitStr = m.value()?.parse()?;
                name = s.value();
            } else if m.input.peek(syn::Token![=]) {
                let _: syn::Expr = m.value()?.parse()?;
            } else if m.input.peek(syn::token::Paren) {
                m.parse_nested_meta(|inner| {
                    if inner.input.peek(syn::Token![=]) {
                        let _: syn::Expr = inner.value()?.parse()?;
                    }
                    Ok(())
                })?;
            }
            Ok(())
        });
    }
    Ok(name)
}

fn struct_attrs(input: &DeriveInput) -> Result<(LitStr, Option<LitStr>)> {
    let mut description = None;
    let mut version = None;
    for attr in input.attrs.iter().filter(|a| a.path().is_ident("sensr")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("description") {
                description = Some(meta.value()?.parse::<LitStr>()?);
            } else if meta.path.is_ident("version") {
                let v: LitStr = meta.value()?.parse()?;
                let ok = v.value().split('.').count() == 3
                    && v.value().split('.').all(|p| p.parse::<u16>().is_ok());
                if !ok {
                    return Err(Error::new(v.span(), "version must be major.minor.patch"));
                }
                version = Some(v);
            } else {
                return Err(meta.error("unknown sensr model attribute"));
            }
            Ok(())
        })?;
    }
    match description {
        Some(d) if !d.value().trim().is_empty() && !d.value().contains('\n') => Ok((d, version)),
        Some(d) => Err(lint(
            d.span(),
            1,
            "the description must be a single, non-empty line",
        )),
        None => Err(lint(
            input.ident.span(),
            1,
            "#[sensr(description = \"...\")] is required",
        )),
    }
}

struct FieldInfo<'a> {
    ident: &'a Ident,
    ty: &'a Type,
    json: String,
    attrs: FieldAttrs,
}

fn model(input: &DeriveInput) -> Result<TokenStream2> {
    let (description, version) = struct_attrs(input)?;
    let Data::Struct(data) = &input.data else {
        return Err(Error::new(
            input.ident.span(),
            "SensrModel needs a struct with named fields",
        ));
    };
    let Fields::Named(named) = &data.fields else {
        return Err(Error::new(
            input.ident.span(),
            "SensrModel needs a struct with named fields",
        ));
    };
    let mut fields = Vec::new();
    for f in &named.named {
        fields.push(FieldInfo {
            ident: f
                .ident
                .as_ref()
                .ok_or_else(|| Error::new(input.ident.span(), "unnamed field"))?,
            ty: &f.ty,
            json: json_name(f)?,
            attrs: field_attrs(f)?,
        });
    }
    let known: Vec<String> = fields.iter().map(|f| f.ident.to_string()).collect();
    for f in &fields {
        for c in &f.attrs.constraints {
            for w in c.with.iter().chain(c.field.iter()) {
                if !known.contains(&w.to_string()) {
                    return Err(Error::new(
                        w.span(),
                        format!("no field `{w}` in this model"),
                    ));
                }
            }
        }
    }

    let name = &input.ident;
    let (impl_g, ty_g, where_g) = input.generics.split_for_impl();
    let s = quote!(::sensr_schema);

    let version_tokens = match &version {
        Some(v) => {
            let parts: Vec<u16> = v
                .value()
                .split('.')
                .map(|p| p.parse().unwrap_or(0))
                .collect();
            let (a, b, c) = (parts[0], parts[1], parts[2]);
            quote!(::core::option::Option::Some(#s::SchemaVersion::new(#a, #b, #c)))
        }
        None => quote!(::core::option::Option::None),
    };

    let metas = fields.iter().map(|f| {
        let n = &f.json;
        let req = f.attrs.required;
        let multiple = f.attrs.multiple;
        let opt = |o: &Option<LitStr>| match o {
            Some(l) => quote!(::core::option::Option::Some(#l)),
            None => quote!(::core::option::Option::None),
        };
        let (d, m, b) = (opt(&f.attrs.default), opt(&f.attrs.message), opt(&f.attrs.blank_desc));
        quote!(#s::model::FieldMeta { name: #n, required: #req, default: #d, message: #m, blank_desc: #b, multiple: #multiple })
    });

    let defaults = fields.iter().map(|f| {
        let id = f.ident;
        let ty = f.ty;
        match &f.attrs.default {
            Some(d) => quote!(#id: #s::model::parse_default::<#ty>(#d)),
            None => quote!(#id: ::core::default::Default::default()),
        }
    });

    let mut checks = Vec::new();
    for f in &fields {
        let id = f.ident;
        let json = &f.json;
        let path = quote!(at.join(#json));
        if f.attrs.required {
            checks.push(quote! {
                if !#s::constraints::ConstraintValue::is_set(&self.#id) {
                    out.push(#path, #s::FieldError::required());
                }
            });
        }
        if let Some((min, max)) = &f.attrs.range {
            let msg = f
                .attrs
                .message
                .as_ref()
                .map_or_else(|| quote!("Invalid integer value."), |m| quote!(#m));
            checks.push(quote! {
                if let ::core::option::Option::Some(v) = #s::constraints::ConstraintValue::as_f64(&self.#id) {
                    #[allow(clippy::cast_precision_loss)]
                    if v < (#min as f64) || v > (#max as f64) {
                        out.add(&#path, #s::ValidatorKind::MinMax, #msg);
                    }
                }
            });
        }
        if f.attrs.nested {
            checks.push(quote!(#s::Validate::validate(&self.#id, ctx, &#path, out);));
        }
        for c in &f.attrs.constraints {
            let refs = |ids: &[Ident]| {
                ids.iter()
                    .map(|w| quote!(&self.#w as &dyn #s::constraints::ConstraintValue))
                    .collect::<Vec<_>>()
            };
            let me = quote!(&self.#id as &dyn #s::constraints::ConstraintValue);
            let msg = |default: TokenStream2| c.message.as_ref().map_or(default, |m| quote!(#m));
            let cm = quote!(#s::constraints::messages);
            let test = match c.kind.as_str() {
                "all_or_none" => {
                    let others = refs(&c.with);
                    let m = msg(quote!(#cm::ALL_OR_NONE));
                    quote!((#s::constraints::all_or_none(&[#me, #(#others),*]), #m))
                }
                "single_select" => {
                    let others = refs(&c.with);
                    let m = msg(quote!(#cm::SINGLE_SELECT));
                    let req = f.attrs.required;
                    quote!((#s::constraints::single_select(&[#me, #(#others),*], #req), #m))
                }
                "set" => {
                    let others = refs(&c.with);
                    let m = msg(quote!(#cm::REQUIRED_WITH));
                    quote!((#s::constraints::set(#me, &[#(#others),*]), #m))
                }
                "depend" => {
                    let others = refs(&c.with);
                    let m = msg(quote!(#cm::REQUIRED_WITH));
                    quote!((#s::constraints::depend(#me, &[#(#others),*]), #m))
                }
                "set_if" => {
                    let other = c
                        .field
                        .as_ref()
                        .map(|w| quote!(&self.#w))
                        .unwrap_or_default();
                    let check = c.check.as_ref();
                    let m = msg(quote!(#cm::REQUIRED_IF));
                    quote!((#s::constraints::set_if(#me, #other, #check), #m))
                }
                "compared" => {
                    let other = c
                        .field
                        .as_ref()
                        .map(|w| quote!(&self.#w))
                        .unwrap_or_default();
                    let op = match c.op.as_ref().map(LitStr::value).as_deref() {
                        Some("gt") => quote!(Gt),
                        Some("gte") => quote!(Gte),
                        Some("lt") => quote!(Lt),
                        Some("lte") => quote!(Lte),
                        Some("eq") => quote!(Eq),
                        _ => quote!(Neq),
                    };
                    let m = msg(quote!(#cm::COMPARED));
                    quote!((#s::constraints::compared(#me, #s::constraints::Comparison::#op, #other), #m))
                }
                _ => continue,
            };
            checks.push(quote! {
                let (ok, msg) = #test;
                if !ok {
                    out.add(&#path, #s::ValidatorKind::Constraint, msg);
                }
            });
        }
    }

    let mut collection = Vec::new();
    for f in &fields {
        for c in f.attrs.constraints.iter().filter(|c| c.kind == "unique") {
            let id = f.ident;
            let json = &f.json;
            let with = &c.with;
            let req = f.attrs.required;
            let ci = c.case_insensitive;
            let m = c
                .message
                .as_ref()
                .map_or_else(|| quote!(#s::constraints::messages::UNIQUE), |m| quote!(#m));
            collection.push(quote! {
                let hits = #s::constraints::unique(
                    items.iter().map(|(uuid, it)| {
                        (*uuid, &it.#id as &dyn #s::constraints::ConstraintValue,
                         ::std::vec![#(&it.#with as &dyn #s::constraints::ConstraintValue),*])
                    }),
                    #s::constraints::UniqueOptions { required: #req, case_insensitive: #ci },
                );
                for uuid in hits {
                    out.add(&at.join(uuid).join(#json), #s::ValidatorKind::Constraint, #m);
                }
            });
        }
    }

    let text_arms = fields.iter().map(|f| {
        let json = &f.json;
        let ty = f.ty;
        let req = f.attrs.required;
        let msg = f.attrs.message.as_ref().map_or_else(
            || quote!(::core::option::Option::None),
            |m| quote!(::core::option::Option::Some(#m)),
        );
        let range = match &f.attrs.range {
            Some((min, max)) => quote!(::core::option::Option::Some((#min as i64, #max as i64))),
            None => quote!(::core::option::Option::None),
        };
        quote!(#json => #s::model::validate_text::<#ty>(text, #req, #range, #msg),)
    });

    let test_name = format_ident!("__sensr_defaults_parse_{}", name.to_string().to_lowercase());

    Ok(quote! {
        impl #impl_g #s::model::SensrModel for #name #ty_g #where_g {
            const DESCRIPTION: &'static str = #description;
            const VERSION: ::core::option::Option<#s::SchemaVersion> = #version_tokens;

            fn fields() -> &'static [#s::model::FieldMeta] {
                &[#(#metas),*]
            }

            fn defaults() -> Self {
                Self { #(#defaults),* }
            }

            fn validate_text(field: &str, text: &str) -> ::std::vec::Vec<#s::FieldError> {
                match field {
                    #(#text_arms)*
                    other => ::std::vec![#s::FieldError::callback(::std::format!("Unknown field {other}."))],
                }
            }
        }

        impl #impl_g #s::Validate for #name #ty_g #where_g {
            #[allow(unused_variables)]
            fn validate(&self, ctx: &dyn #s::RefContext, at: &#s::FieldPath, out: &mut #s::Validations) {
                #(#checks)*
            }
        }

        impl #impl_g #s::model::SensrItem for #name #ty_g #where_g {
            #[allow(unused_variables)]
            fn validate_collection(items: &#s::ArrayField<Self>, at: &#s::FieldPath, out: &mut #s::Validations) {
                #(#collection)*
            }
        }

        #[cfg(test)]
        #[test]
        #[allow(non_snake_case)]
        fn #test_name() {
            // Every `default = ".."` literal must parse into its field type.
            let _ = <#name as #s::model::SensrModel>::defaults();
        }
    })
}

/// serde `rename_all` value of an enum, if any.
fn rename_all(input: &DeriveInput) -> Option<String> {
    let mut out = None;
    for attr in input.attrs.iter().filter(|a| a.path().is_ident("serde")) {
        let _ = attr.parse_nested_meta(|m| {
            if m.path.is_ident("rename_all") {
                out = Some(m.value()?.parse::<LitStr>()?.value());
            } else if m.input.peek(syn::Token![=]) {
                let _: syn::Expr = m.value()?.parse()?;
            }
            Ok(())
        });
    }
    out
}

fn case(name: &str, rule: Option<&str>) -> String {
    let words = || {
        let mut w = String::new();
        for (i, c) in name.chars().enumerate() {
            if c.is_uppercase() && i > 0 {
                w.push('_');
            }
            w.extend(c.to_lowercase());
        }
        w
    };
    match rule {
        Some("lowercase") => name.to_lowercase(),
        Some("UPPERCASE") => name.to_uppercase(),
        Some("snake_case") => words(),
        Some("SCREAMING_SNAKE_CASE") => words().to_uppercase(),
        Some("kebab-case") => words().replace('_', "-"),
        _ => name.to_owned(),
    }
}

fn options(input: &DeriveInput) -> Result<TokenStream2> {
    let Data::Enum(data) = &input.data else {
        return Err(Error::new(input.ident.span(), "SensrOptions needs an enum"));
    };
    let rule = rename_all(input);
    let mut pairs = Vec::new();
    for v in &data.variants {
        let mut key = case(&v.ident.to_string(), rule.as_deref());
        let mut label = None;
        for attr in &v.attrs {
            if attr.path().is_ident("sensr") {
                attr.parse_nested_meta(|m| {
                    if m.path.is_ident("label") {
                        label = Some(m.value()?.parse::<LitStr>()?);
                        Ok(())
                    } else {
                        Err(m.error("unknown sensr option attribute"))
                    }
                })?;
            } else if attr.path().is_ident("serde") {
                let _ = attr.parse_nested_meta(|m| {
                    if m.path.is_ident("rename") {
                        key = m.value()?.parse::<LitStr>()?.value();
                    }
                    Ok(())
                });
            }
        }
        let label = label.ok_or_else(|| {
            Error::new(
                v.ident.span(),
                "every option needs #[sensr(label = \"...\")]",
            )
        })?;
        if label.value() == key {
            return Err(lint(
                label.span(),
                16,
                "the option label must differ from its key",
            ));
        }
        pairs.push(quote!((#key, #label)));
    }
    let name = &input.ident;
    let s = quote!(::sensr_schema);
    Ok(quote! {
        impl #s::model::SensrOptions for #name {
            fn options() -> &'static [(&'static str, &'static str)] {
                &[#(#pairs),*]
            }
        }
    })
}
