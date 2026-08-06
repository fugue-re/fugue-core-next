use std::any::Any;
use std::collections::BTreeMap;
use std::sync::Arc;

use super::{IlProduced, IlRegistry};
use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlConverter, IlError, IlFormId, IlGenerationContext, IlGenerationError, IlProducer,
};

type IlConverterFactory = fn() -> Box<dyn ErasedIlConverter>;
type IlProducerFactory = fn() -> Box<dyn ErasedIlProducer>;

#[derive(Debug, Clone, Copy)]
pub(crate) enum IlRecipe {
    Converter(IlConverterFactory),
    Producer(IlProducerFactory),
}

impl IlRecipe {
    pub(crate) const fn converter<T: IlConverter>() -> Self {
        Self::Converter(new_converter::<T>)
    }

    pub(crate) const fn producer<T: IlProducer>() -> Self {
        Self::Producer(new_producer::<T>)
    }

    fn instantiate(self) -> IlRecipeExecutor {
        match self {
            Self::Converter(factory) => IlRecipeExecutor::Converter(factory()),
            Self::Producer(factory) => IlRecipeExecutor::Producer(factory()),
        }
    }
}

pub(crate) trait ErasedIlConverter: Send {
    fn convert(
        &mut self,
        source: &(dyn Any + Send + Sync),
        context: &IlGenerationContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<IlProduced, IlGenerationError>;
}

impl<T: IlConverter> ErasedIlConverter for T {
    fn convert(
        &mut self,
        source: &(dyn Any + Send + Sync),
        context: &IlGenerationContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<IlProduced, IlGenerationError> {
        let source = source
            .downcast_ref::<T::Input>()
            .ok_or_else(|| IlGenerationError::Il(IlError::mismatched_source(T::Input::FORM)))?;

        Ok(Box::new(T::convert(self, source, context, cancellation)?))
    }
}

pub(crate) trait ErasedIlProducer: Send {
    fn produce(
        &mut self,
        context: &IlGenerationContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<IlProduced, IlGenerationError>;
}

impl<T: IlProducer> ErasedIlProducer for T {
    fn produce(
        &mut self,
        context: &IlGenerationContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<IlProduced, IlGenerationError> {
        Ok(Box::new(T::produce(self, context, cancellation)?))
    }
}

fn new_converter<T: IlConverter>() -> Box<dyn ErasedIlConverter> {
    Box::new(T::default())
}

fn new_producer<T: IlProducer>() -> Box<dyn ErasedIlProducer> {
    Box::new(T::default())
}

enum IlRecipeExecutor {
    Converter(Box<dyn ErasedIlConverter>),
    Producer(Box<dyn ErasedIlProducer>),
}

pub(crate) struct GeneratedIl {
    artefacts: Vec<GeneratedArtefact>,
}

impl GeneratedIl {
    fn new() -> Self {
        Self {
            artefacts: Vec::new(),
        }
    }

    pub(crate) fn into_artefacts(self) -> Vec<GeneratedArtefact> {
        self.artefacts
    }

    pub(crate) fn into_requested(self) -> Option<IlProduced> {
        self.artefacts
            .into_iter()
            .next_back()
            .map(GeneratedArtefact::into_value)
    }

    fn last(&self) -> Option<&(dyn Any + Send + Sync)> {
        self.artefacts
            .last()
            .map(|artefact| artefact.value.as_ref())
    }

    fn push(&mut self, form: IlFormId, artefact: IlProduced) {
        self.artefacts.push(GeneratedArtefact::new(form, artefact));
    }
}

pub(crate) struct GeneratedArtefact {
    form: IlFormId,
    value: IlProduced,
}

impl GeneratedArtefact {
    fn new(form: IlFormId, value: IlProduced) -> Self {
        Self { form, value }
    }

    pub(crate) fn form(&self) -> &IlFormId {
        &self.form
    }

    pub(crate) fn into_value(self) -> IlProduced {
        self.value
    }
}

pub(crate) struct IlGenerationSession {
    recipes: BTreeMap<IlFormId, IlRecipeExecutor>,
}

impl IlGenerationSession {
    pub(crate) fn new(registry: &IlRegistry) -> Self {
        let recipes = registry
            .forms()
            .filter_map(|registration| {
                registration
                    .recipe()
                    .map(|recipe| (registration.form().clone(), recipe.instantiate()))
            })
            .collect();
        Self { recipes }
    }

    pub(crate) fn generate(
        &mut self,
        registry: &IlRegistry,
        form: &IlFormId,
        existing: impl IntoIterator<Item = Option<Arc<dyn Any + Send + Sync>>>,
        context: &IlGenerationContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<GeneratedIl, IlGenerationError> {
        if registry.form(form).is_none() {
            return Err(IlError::unregistered_form(form.clone()).into());
        }

        let mut existing = existing.into_iter();
        let mut generated = GeneratedIl::new();
        let mut current = None::<Arc<dyn Any + Send + Sync>>;
        let mut produced_previous = false;

        for step in registry.canonical_path(form) {
            if let Some(artefact) = existing.next().flatten() {
                current = Some(artefact);
                produced_previous = false;
                continue;
            }

            let Some(recipe) = self.recipes.get_mut(step) else {
                return Err(IlError::missing_recipe(step.clone()).into());
            };
            let artefact = match recipe {
                IlRecipeExecutor::Producer(producer) => producer.produce(context, cancellation)?,
                IlRecipeExecutor::Converter(converter) => {
                    let source = if produced_previous {
                        generated
                            .last()
                            .expect("the previous recipe recorded its artefact")
                    } else {
                        current.as_deref().ok_or_else(|| {
                            IlGenerationError::Il(IlError::missing_artefact(
                                context.function(),
                                step.clone(),
                            ))
                        })?
                    };
                    converter.convert(source, context, cancellation)?
                }
            };

            generated.push(step.clone(), artefact);
            current = None;
            produced_previous = true;
        }

        Ok(generated)
    }
}
