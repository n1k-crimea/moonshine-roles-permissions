<?php

namespace Sweet1s\MoonshineRBAC\FormComponents;

use Closure;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use MoonShine\Components\FormBuilder;
use MoonShine\Components\MoonShineComponent;
use MoonShine\Decorations\Column;
use MoonShine\Decorations\Divider;
use MoonShine\Decorations\Grid;
use MoonShine\Fields\Select;
use MoonShine\Fields\Switcher;
use MoonShine\MoonShineAuth;
use MoonShine\Resources\ModelResource;
use MoonShine\Traits\HasResource;
use MoonShine\Traits\WithLabel;
use Sweet1s\MoonshineRBAC\Traits\WithRolePermissions;

final class RolePermissionsFormComponent extends MoonShineComponent
{
    protected string $view = 'moonshine-rbac::form-components.permissions';
    protected bool $all = true;
    protected array $values = [];
    protected array $elements = [];

    use HasResource;
    use WithLabel;

    protected $except = [
        'getItem',
        'getResource',
        'getForm',
    ];

    public function __construct(
        Closure|string $label,
        ModelResource $resource
    ) {
        $this->setResource($resource);
        $this->setLabel($label);
    }

    public function getItem(): Model
    {
        return $this->getResource()->getItemOrInstance();
    }

    public function getForm(): FormBuilder
    {
        $currentUser = MoonShineAuth::guard()->user();

        foreach (moonshine()->getResources() as $resource) {
            $checkboxes = [];
            $class = class_basename($resource::class);
            $allSections = true;

            if (!in_array(WithRolePermissions::class, class_uses($resource))) {
                continue;
            }

            foreach ($resource->gateAbilities() as $ability) {
                $hasPermission = false;

                foreach ($currentUser->roles as $role) {
                    if ($role->isHavePermission($class, $ability)) {
                        $hasPermission = true;
                        break;
                    }
                }

                if (!$hasPermission) {
                    continue;
                }

                $this->values['permissions'][$class][$ability] = $this->getItem()?->isHavePermission(
                    $class,
                    $ability
                );

                if (!$this->values['permissions'][$class][$ability]) {
                    $allSections = false;
                    $this->all = false;
                }

                $checkboxes[] = Switcher::make(
                    trans("moonshine-rbac::ui.$ability"),
                    "permissions." . $class . ".$ability"
                )
                    ->customAttributes(['class' => 'permission_switcher ' . $class])
                    ->setName("permissions[" . $class . "][$ability]");
            }

            if (empty($checkboxes)) {
                continue;
            }

            $this->elements[] = Column::make([
                Switcher::make($resource->title())->customAttributes([
                    'class' => 'permission_switcher_section',
                    '@change' => "document
                          .querySelectorAll('.$class')
                          .forEach((el) => {el.checked = !parseInt(event.target.value); el.dispatchEvent(new Event('change'))})",
                ])->setValue($allSections)->hint('Общий переключатель ВКЛ/ВЫКЛ'),
                Divider::make(),
            ])->columnSpan(6);
        }

        $this->customPermissions($currentUser);

        return FormBuilder::make(route('moonshine-rbac.roles.attach-permissions-to-role', $this->getItem()->getKey()))
            ->fields([
                $this->priorityField(),
                Divider::make(),
                Switcher::make(trans('moonshine-rbac::ui.all'))->customAttributes([
                    '@change' => <<<'JS'
                        document
                          .querySelectorAll('.permission_switcher, .permission_switcher_section')
                          .forEach((el) => {el.checked = !parseInt(event.target.value); el.dispatchEvent(new Event('change'))})
                    JS,
                ])->setValue($this->all),
                Divider::make(),
                Grid::make(
                    $this->elements
                ),
            ])
            ->fill($this->values)
            ->submit(__('moonshine::ui.save'));
    }

    public function priorityField()
    {
        return Select::make(trans('moonshine-rbac::ui.can_give_the_roles'))
            ->options(
                config('permission.models.role')::where('id', '!=', config('moonshine.auth.providers.moonshine.model')::SUPER_ADMIN_ROLE_ID)
                    ->get()
                    ->pluck('name', 'id')
                    ->toArray()
            )
            ->default($this->getItem()->role_priority)
            ->searchable()
            ->multiple()
            ->setName('role_priority[]');
    }

    protected function viewData(): array
    {
        return [
            'label' => $this->label(),
            'form' => $this->getItem()?->exists
                ? $this->getForm()
                : '',
            'item' => $this->getItem(),
            'resource' => $this->getResource(),
        ];
    }

    /**
     * @param $currentUser
     * @return void
     */
    protected function customPermissions($currentUser): void
    {
        $checkboxes = [];
        $allSelections = true;

        foreach (config('permission.models.permission')::where('name', 'LIKE', '%Custom.%')->get() as $permission) {
            $hasPermission = false;

            foreach ($currentUser->roles as $role) {
                if ($role->isHavePermission(permission: $permission->name)) {
                    $hasPermission = true;
                    break;
                }
            }

            if (!$hasPermission) {
                continue;
            }

            $permission->name = Str::remove('Custom.', $permission->name);
            $this->values['permissions']['Custom'][$permission->name] = $this->getItem()?->isHavePermission(permission: 'Custom.' . $permission->name);

            if (!$this->values['permissions']['Custom'][$permission->name]) {
                $allSelections = false;
                $this->all = false;
            }

            $checkboxes[] = Switcher::make(
                $permission->name,
                "permissions.Custom." . $permission->name
            )
                ->customAttributes(['class' => 'permission_switcher ' . 'customs'])
                ->setName("permissions[Custom][$permission->name]");
        }

        $checkboxes = collect($checkboxes)->split(2)->toArray();

        if (!empty($checkboxes)) {
            $this->elements[] = Column::make([
                Switcher::make(trans('moonshine-rbac::ui.custom'))->customAttributes([
                    'class' => 'permission_switcher_section',
                    '@change' => "document
                          .querySelectorAll('.customs')
                          .forEach((el) => {el.checked = !parseInt(event.target.value); el.dispatchEvent(new Event('change'))})",
                ])->setValue($allSelections)->hint('Toggle off/on all'),

                Divider::make(),

                Grid::make([
                    Column::make([
                        ...$checkboxes[0] ?? [],
                    ])->columnSpan(6),
                    Column::make([
                        ...$checkboxes[1] ?? [],
                    ])->columnSpan(6),
                ]),

                Divider::make(),
            ])->columnSpan(12);
        }
    }
}
