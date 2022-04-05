#ifndef FILTERHELPER_HPP
#define FILTERHELPER_HPP
#if defined(_MSC_VER)
#pragma warning(disable: 4345)
#endif
#include <boost/spirit/home/x3.hpp>
#include <boost/spirit/home/x3/support/ast/variant.hpp>
#include <boost/fusion/include/adapt_struct.hpp>
#include <iostream>
#include <string>
#include <list>
#include <numeric>
namespace x3 = boost::spirit::x3;
namespace filter {
    namespace ast
    {
        struct ipv6_address {
            std::vector<uint16_t> address;
            int insert_position = -1;
        };
        struct address:std::vector<uint8_t> {
            inline address(){}
            inline address(const ipv6_address& x) {
                this->clear();
                auto t = x.address;
                if (x.address.size() < 8) {
                    for (int i = 0; i < x.insert_position; i++) {
                        this->push_back(x.address[i] / 256);
                        this->push_back(x.address[i] % 256);
                    }
                    for (int i = x.address.size(); i < 8; i++) {
                        this->push_back(0); this->push_back(0);
                    }
                    for (int i = x.insert_position; i < x.address.size(); i++) {
                        this->push_back(x.address[i] / 256);
                        this->push_back(x.address[i] % 256);
                    }
                }
            }
        };
        struct constant_value : x3::variant<
            address,
            uint64_t,
            double,
            bool
        > {
            using base_type::base_type;
            using base_type::operator=;
        };

        struct property_path : std::string{};
        struct property_path_tag:std::string{};

        struct ast_value : x3::variant<
            constant_value,
            property_path
        > {
            using base_type::base_type;
            using base_type::operator=;
        };
        struct filter_rule;
        struct binop {
            ast_value op1;
            std::string tag;
            ast_value op2;
        };
        struct b_expr :public x3::variant<
            binop,
            x3::forward_ast<filter_rule>,
            property_path
        > {
            using base_type::base_type;
            using base_type::operator=;
        };;
        struct clousure_value :std::vector<b_expr> {};
        struct filter_rule :std::vector<clousure_value> {};
    }
}
BOOST_FUSION_ADAPT_STRUCT(filter::ast::ipv6_address, address, insert_position);
BOOST_FUSION_ADAPT_STRUCT(filter::ast::binop, op1, tag, op2);
namespace filter
{
    ///////////////////////////////////////////////////////////////////////////////
    //  The calculator grammar
    ///////////////////////////////////////////////////////////////////////////////
    namespace filter_grammar
    {

        x3::rule<class conjunctive,ast::filter_rule> const conjunctive("conjunctive");
        x3::rule<class clousure,ast::clousure_value> const clousure("clousure");
        x3::rule<class basic_expr,ast::b_expr> const basic_expr("basic_expr");
        x3::rule<class binop_expr,ast::binop> const binop_expr("basic_expr");
        x3::rule<class value_expr, ast::ast_value> const value_expr("value_expr");

        x3::rule<class protocol_or_field,ast::property_path> const property_path_expr("property_path_expr");
        x3::rule<class protocol_or_field,ast::property_path_tag> const property_tag_expr("property_tag_expr");

        x3::rule<class constant_value,ast::constant_value> const constant_value_expr("constant_value_expr");

        x3::rule<class ipv4_constant,  ast::address> const ipv4_constant("ipv4_constant");
        x3::rule<class ipv6_constant, ast::ipv6_address> const ipv6_constant("ipv6_constant");
        x3::rule<class mac_constant,ast::address> const mac_constant("mac_constant");


        auto const conjunctive_def = clousure % "||";
        auto const clousure_def = basic_expr % "&&";
        auto const basic_expr_def =
            binop_expr |
            ('(' >> conjunctive >> ')')|
            property_path_expr
            ;
        auto const binop_expr_def =
            (value_expr >> x3::string("==") >> value_expr) |
            (value_expr >> x3::string("!=") >> value_expr) |
            (value_expr >> x3::string(">=") >> value_expr) |
            (value_expr >> x3::string("<=") >> value_expr) |
            (value_expr >> x3::string(">") >> value_expr) |
            (value_expr >> x3::string("<") >> value_expr);
        auto const value_expr_def = property_path_expr | constant_value_expr;

        auto const property_path_expr_def = property_tag_expr[([](auto& ctx) {x3::_val(ctx)+=(x3::_attr(ctx));})]
                >> *(x3::char_('.')>>property_tag_expr[([](auto& ctx) {x3::_val(ctx)+=std::string(".")+(x3::_attr(ctx));})]);
        //auto const property_path_expr_def = property_tag_expr[([](auto& ctx) {x3::_val(ctx)+="."+(x3::_attr(ctx));})] % '.';

        auto const property_tag_expr_def = x3::alpha >> *x3::alnum;

        auto const constant_value_expr_def = ipv4_constant | ipv6_constant | mac_constant | x3::uint64 | x3::double_ |x3::bool_;
        auto const ipv4_constant_def = x3::uint8[([](auto& ctx) {x3::_val(ctx).push_back(x3::_attr(ctx)); })]
            >> x3::repeat(3)['.' >> x3::uint8[([](auto& ctx) { x3::_val(ctx).push_back(x3::_attr(ctx)); })]];
        auto const mac_constant_def = x3::hex[([](auto& ctx) {x3::_val(ctx).push_back(x3::_attr(ctx)); })]
            >> x3::repeat(5)[':' >> x3::hex[([](auto& ctx) {x3::_val(ctx).push_back(x3::_attr(ctx)); })]];
        auto const ipv6_constant_def =
            (
                (!(x3::hex[([](auto& ctx) {x3::_val(ctx).address.push_back(x3::_attr(ctx)); })] % ':')) >>
                x3::lit("::")[([](auto& ctx) {x3::_val(ctx).insert_position = x3::_val(ctx).address.size(); })] >>
                (!(x3::hex[([](auto& ctx) {x3::_val(ctx).address.push_back(x3::_attr(ctx)); })] % ':'))
                ) |

            (
                x3::hex[([](auto& ctx) {x3::_val(ctx).address.push_back(x3::_attr(ctx)); })] >>
                x3::repeat(7)[':' >> x3::hex[([](auto& ctx) {x3::_val(ctx).address.push_back(x3::_attr(ctx)); })]]
                );
            ;
        BOOST_SPIRIT_DEFINE(conjunctive, clousure, basic_expr,binop_expr, value_expr, property_path_expr,property_tag_expr, constant_value_expr,ipv4_constant,ipv6_constant,mac_constant);

        auto filter = conjunctive;
    }

    using filter_grammar::filter;

}

#endif // FILTERHELPER_HPP
