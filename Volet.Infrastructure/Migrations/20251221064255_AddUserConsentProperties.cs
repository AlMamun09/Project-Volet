using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Volet.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddUserConsentProperties : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "HasAcceptedNewsletterAndAnalytics",
                table: "AspNetUsers",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "HasAcceptedPrivacyPolicy",
                table: "AspNetUsers",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "HasAcceptedUserAgreement",
                table: "AspNetUsers",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "HasAcceptedNewsletterAndAnalytics",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "HasAcceptedPrivacyPolicy",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "HasAcceptedUserAgreement",
                table: "AspNetUsers");
        }
    }
}
