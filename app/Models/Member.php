<?php
// Updated Member.php with activation_code, password_reset_code, and positions
namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Laravel\Sanctum\HasApiTokens;
use AllowDynamicProperties;

#[AllowDynamicProperties]
class Member extends Authenticatable
{
    use HasFactory, Notifiable, HasApiTokens;

    // Role constants
    public const string ROLE_ADMIN = 'role_admin';
    public const string ROLE_MODERATOR = 'role_moderator';
    public const string ROLE_USER = 'role_user';
    public const string ROLE_NONE = 'role_none';

    // Position constants
    public const string POSITION_MEMBER = 'członek koła';
    public const string POSITION_GUARDIAN = 'opiekun';
    public const string POSITION_CHAIRMAN = 'przewodniczący';
    public const string POSITION_VICE_CHAIRMAN = 'wiceprzewodniczący';
    public const string POSITION_TREASURER = 'skarbnik';

    // Position translations
    public const array POSITION_TRANSLATIONS = [
        self::POSITION_MEMBER => 'Member',
        self::POSITION_GUARDIAN => 'Guardian',
        self::POSITION_CHAIRMAN => 'Chairman',
        self::POSITION_VICE_CHAIRMAN => 'Vice-chairman',
        self::POSITION_TREASURER => 'Treasurer',
    ];

    // Role permissions mapping
    private const array ROLE_PERMISSIONS = [
        self::ROLE_ADMIN => [
            'manage_users',
            'manage_roles',
            'manage_content',
            'delete_content',
            'deactivate_users',
            'create_users',
        ],
        self::ROLE_MODERATOR => [
            'manage_content',
            'delete_content',
            'moderate_users'
        ],
        self::ROLE_USER => [
        ],
        self::ROLE_NONE => []
    ];

    protected $fillable = [
        'first_name',
        'last_name',
        'email',
        'password',
        'role',
        'position',
        'deactivation_date',
        'is_active',
        'visible',
        'photo',
        'description',
        'activation_code',
        'password_reset_code'
    ];

    protected $hidden = [
        'password',
        'activation_code',
        'password_reset_code',
    ];

    protected $casts = [
        'is_active' => 'boolean',
        'visible' => 'boolean',
        'deactivation_date' => 'datetime'
    ];

    /**
     * Get all available roles
     *
     * @return array<string>
     */
    public static function getAvailableRoles(): array
    {
        return [
            self::ROLE_ADMIN,
            self::ROLE_MODERATOR,
            self::ROLE_USER,
            self::ROLE_NONE
        ];
    }

    /**
     * Get all available positions
     *
     * @return array<string>
     */
    public static function getAvailablePositions(): array
    {
        return [
            self::POSITION_MEMBER,
            self::POSITION_GUARDIAN,
            self::POSITION_CHAIRMAN,
            self::POSITION_VICE_CHAIRMAN,
            self::POSITION_TREASURER,
        ];
    }

    /**
     * Get translated position name
     *
     * @return string
     */
    public function getTranslatedPosition(): string
    {
        return self::POSITION_TRANSLATIONS[$this->position] ?? $this->position;
    }

    /**
     * Check if user has specified role
     *
     * @param string $role
     * @return bool
     */
    public function hasRole(string $role): bool
    {
        return $this->role === $role;
    }

    /**
     * Check if user is admin
     *
     * @return bool
     */
    public function isAdmin(): bool
    {
        return $this->hasRole(self::ROLE_ADMIN);
    }

    /**
     * Check if user is moderator
     *
     * @return bool
     */
    public function isModerator(): bool
    {
        return $this->hasRole(self::ROLE_MODERATOR);
    }

    /**
     * Check if user is active
     *
     * @return bool
     */
    public function isActiveUser(): bool
    {
        return $this->is_active && $this->role !== self::ROLE_NONE;
    }

    /**
     * Get all permissions for current role
     *
     * @return array<string>
     */
    public function getPermissions(): array
    {
        return self::ROLE_PERMISSIONS[$this->role] ?? [];
    }

    /**
     * Check if user has specific permission
     *
     * @param string $permission
     * @return bool
     */
    public function hasPermission(string $permission): bool
    {
        return in_array($permission, $this->getPermissions());
    }

    /**
     * Check if user has any of specified permissions
     *
     * @param array<string> $permissions
     * @return bool
     */
    public function hasAnyPermission(array $permissions): bool
    {
        return !empty(array_intersect($permissions, $this->getPermissions()));
    }

    /**
     * Full name accessor
     *
     * @return \Illuminate\Database\Eloquent\Casts\Attribute
     */
    protected function fullName(): Attribute
    {
        return Attribute::make(
            get: fn () => "{$this->first_name} {$this->last_name}",
        );
    }

    /**
     * Visible attribute accessor/mutator
     *
     * @return \Illuminate\Database\Eloquent\Casts\Attribute
     */
    protected function visible(): Attribute
    {
        return Attribute::make(
            get: fn ($value) => (bool) $value,
            set: fn ($value) => (bool) $value,
        );
    }

    /**
     * Check if profile is visible
     *
     * @return bool
     */
    public function isVisible(): bool
    {
        return (bool) $this->visible;
    }

    /**
     * Make profile visible
     *
     * @return self
     */
    public function showProfile(): self
    {
        $this->visible = true;
        return $this;
    }

    /**
     * Hide profile
     *
     * @return self
     */
    public function hideProfile(): self
    {
        $this->visible = false;
        return $this;
    }

    /**
     * Profile photo relationship
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function profilePhoto(): BelongsTo
    {
        return $this->belongsTo(File::class, 'photo');
    }

    /**
     * Posts relationship
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function posts(): HasMany
    {
        return $this->hasMany(Post::class, 'author_id');
    }

    /**
     * Events relationship
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function events(): HasMany
    {
        return $this->hasMany(Event::class, 'author_id');
    }

    /**
     * Uploaded files relationship
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function uploadedFiles(): HasMany
    {
        return $this->hasMany(File::class, 'uploaded_by');
    }
}
