using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Volet.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class Add2FAProperties : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AuthenticatorSecretKey",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsAuthenticatorConfirmed",
                table: "AspNetUsers",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "IsTwoFactorEnabled",
                table: "AspNetUsers",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "TwoFactorMethod",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AuthenticatorSecretKey",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "IsAuthenticatorConfirmed",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "IsTwoFactorEnabled",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "TwoFactorMethod",
                table: "AspNetUsers");
        }
    }
}
